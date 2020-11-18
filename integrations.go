package gcpiamslack

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"git.sr.ht/~urandom/dwd"
	"github.com/PagerDuty/go-pagerduty"
	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// This file contains code related to GCP and Pagerduty integrations

type ResourceType string

const (
	Projects      ResourceType = "projects"
	Organizations ResourceType = "organizations"
)

type IntegrationClient struct{}

func NewIntegrationClient() *IntegrationClient {
	return &IntegrationClient{}
}

func (i *IntegrationClient) getGroupMembership(r *EscalationRequest) error {
	ctx := context.Background()
	// This is using a 3rd party lib because there is a long standing issue with
	// the interplay between gsuite's admin sdk needing account impersonation and
	// no 1st party support for that with existing GCP API's.

	// https://github.com/googleapis/google-api-go-client/issues/652
	// https://github.com/googleapis/google-api-go-client/issues/379
	ts := dwd.TokenSource(
		ctx,
		// User must be a GSuite admin.
		"jdoliner@pachyderm.io",
		admin.AdminDirectoryGroupReadonlyScope,
	)
	srv, err := admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Errorf("can't initialize admin sdk %v", err)
		return err
	}
	grpSrv := admin.NewGroupsService(srv)
	groups, err := grpSrv.List().Domain("pachyderm.io").UserKey(string(r.Requestor)).Do()
	if err != nil {
		log.Errorf("can't retrieve groups from google: %v", err)
		return err
	}
	for _, g := range groups.Groups {
		r.Groups[group(g.Email)] = struct{}{}
	}
	return nil
}

// TODO: Need to support single project functionality here based on resource
// Attaches specific iam roles to a given user conditionally.
// Notably, this policy overwrites any existing policies.
// If you do not append your policy changes to an existing policy,
// it is very easy to get the gcp organization into a bad state.
// Please take a look at the comment in the critical section before making changes
func (i *IntegrationClient) conditionalBindIAMPolicy(ctx context.Context, r *EscalationRequest) error {
	log.Debug("Getting IAM Policy")

	rscType, err := parseResourceType(r.Resource)
	if err != nil {
		return err
	}

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize google cloudresourcemanager: %v", err)
	}

	userEmail := []string{fmt.Sprintf("user:%s", r.Requestor)}
	start := time.Now()
	hourFromNow := start.Add(time.Hour).Format(time.RFC3339)
	log.Debugf("Timestamp: %s", hourFromNow)
	binding := &cloudresourcemanager.Binding{
		// Conditions cannot be set on primitive roles
		// Error 400: LintValidationUnits/BindingRoleAllowConditionCheck Error: Conditions can't be set on primitive roles
		Role:    string(r.Role),
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
		var existingPolicy *cloudresourcemanager.Policy
		switch rscType {
		case Projects:
			existingPolicy, err = cloudResourceManagerService.Projects.GetIamPolicy(string(r.Resource), getIamPolicyRequest).Context(ctx).Do()
		case Organizations:
			existingPolicy, err = cloudResourceManagerService.Organizations.GetIamPolicy(string(r.Resource), getIamPolicyRequest).Context(ctx).Do()
		}
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
		switch rscType {
		case Projects:
			_, err = cloudResourceManagerService.Projects.SetIamPolicy(string(r.Resource), setIamPolicyRequest).Context(ctx).Do()
		case Organizations:
			_, err = cloudResourceManagerService.Organizations.SetIamPolicy(string(r.Resource), setIamPolicyRequest).Context(ctx).Do()
		}
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

func parseResourceType(resource resource) (ResourceType, error) {
	if strings.HasPrefix(string(resource), "projects/") {
		return Projects, nil
	}
	if strings.HasPrefix(string(resource), "organizations/") {
		return Organizations, nil
	}
	return "", errors.New("unexpected resource type, please check the configuration")
}

// if unable to reach pagerduty - just disables self approval
func (i *IntegrationClient) lookupCurrentOnCall(r *EscalationRequest) bool {
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
			if requestor(user.Email) == r.Requestor {
				return true
			}
		}
	}
	return false
}
