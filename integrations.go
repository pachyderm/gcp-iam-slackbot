package gcpiamslack

import (
	"context"
	"fmt"
	"time"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

// This package contains code related to GCP and Pagerduty integrations

// Attaches specific iam roles to a given user conditionally.
// Notably, this policy overwrites any existing policies.
// If you do not append your policy changes to an existing policy,
// it is very easy to get the gcp organization into a bad state.
// Please take a look at the comment in the critical section before making changes
func conditionalBindIAMPolicy(ctx context.Context, username member, resource resource, IAMRole string) error {
	log.Debug("Getting IAM Policy")

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize google cloudresourcemanager: %v", err)
	}

	userEmail := []string{fmt.Sprintf("user:%s", username)}
	start := time.Now()
	hourFromNow := start.Add(time.Hour).Format(time.RFC3339)
	log.Debugf("Timestamp: %s", hourFromNow)
	binding := &cloudresourcemanager.Binding{
		// Conditions cannot be set on primitive roles
		// Error 400: LintValidationUnits/BindingRoleAllowConditionCheck Error: Conditions can't be set on primitive roles
		Role:    IAMRole,
		Members: userEmail,
		Condition: &cloudresourcemanager.Expr{
			Title:       fmt.Sprintf("Until: %s", hourFromNow),
			Description: "This temporarily grants Hub On Call Escalated privileges for 1 hour",
			Expression:  fmt.Sprintf("request.time < timestamp(\"%s\")", hourFromNow),
		},
	}
	getIamPolicyRequest := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}
	//folderService := cloudresourcemanager.NewFoldersService(cloudResourceManagerService)
	b := &backoff.Backoff{
		Min:    2000 * time.Millisecond,
		Max:    1 * time.Minute,
		Factor: 2,
		Jitter: true,
	}
	for {
		d := b.Duration()
		//existingPolicy
		existingPolicy, err := cloudResourceManagerService.Organizations.GetIamPolicy(string(resource), getIamPolicyRequest).Context(ctx).Do()
		if e, ok := err.(*googleapi.Error); ok {
			if e.Code == 409 {
				time.Sleep(d)
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("failed to retrieve iam policy: %v", err)
		}

		// Please use caution for this section!!
		// It is important that the existing policy is appeneded to.
		// If it is not, the new policy will overwrite the existing policy.
		// This will remove all existing permissions at the gcp org level!
		if existingPolicy == nil {
			return fmt.Errorf("No existing policy was found for the GCP Organization")
		}
		existingPolicy.Bindings = append(existingPolicy.Bindings, binding)
		// In order to use conditional IAM, must set version to 3
		// See https://cloud.google.com/iam/docs/policies#versions
		existingPolicy.Version = 3
		setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: existingPolicy,
		}
		_, err = cloudResourceManagerService.Organizations.SetIamPolicy(string(resource), setIamPolicyRequest).Context(ctx).Do()
		if e, ok := err.(*googleapi.Error); ok {
			if e.Code == 409 {
				time.Sleep(d)
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("failed to set iam policy: %v", err)
		}
		return nil
	}
}

// This function doesn't return an error because it shouldn't be blocking
// if unable to reach pagerduty - just disables self approval
func lookupCurrentOnCall(m member) bool {
	oc, err := client.ListOnCalls(pagerduty.ListOnCallOptions{})
	if err != nil {
		log.Errorf("Unable to lookup pagerduty on calls: %v", err)
		return false
	}
	for _, x := range oc.OnCalls {
		// This is the hardcoded Hub EscalationPolicyID
		if (x.EscalationLevel == 1 || x.EscalationLevel == 2) && x.EscalationPolicy.APIObject.ID == HubEscalationPolicyID {
			user, err := client.GetUser(x.User.APIObject.ID, pagerduty.GetUserOptions{})
			if err != nil {
				log.Errorf("Unable to lookup pagerduty user, %v", err)
				return false
			}
			if member(user.Email) == m {
				return true
			}
		}
	}
	return false
}
