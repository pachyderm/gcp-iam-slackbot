package gcpiamslack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

func handleApproval(message slack.InteractionCallback) error {
	ctx := context.Background()
	actionInfo := strings.Split(message.ActionCallback.BlockActions[0].Value, ",")
	approvalStatus, err := strconv.Atoi(actionInfo[1])
	if err != nil {
		return fmt.Errorf("Unable to parse approval status: %v \n", err)
	}

	r := &EscalationRequest{
		Member:    member(actionInfo[2]),
		Role:      role(actionInfo[3]),
		Resource:  "organizations/6487630834",
		Reason:    actionInfo[5],
		Timestamp: actionInfo[4],
		Status:    approval(approvalStatus),
	}

	profile, err := api.GetUserProfile(message.User.ID, true)
	if err != nil {
		return fmt.Errorf("Unable to get user info from slack API: %v \n", err)
	}
	r.Approver = strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)
	if !strings.HasSuffix(r.Approver, "@pachyderm.io") {
		return fmt.Errorf("Unauthorized User, not from pachyderm.io: %v \n", r.Approver)
	}
	oncall, err := lookupCurrentOnCall()
	if err != nil {
		return fmt.Errorf("Unable to get user info from pagerduty API: %v \n", err)
	}
	// TODO: Remove hardcoded exception for sean for testing
	if string(r.Member) == r.Approver && r.Member != "sean@pachyderm.io" && !oncall[r.Member] {
		return fmt.Errorf("Unauthorized, approver cannot be requester: %v \n", r.Approver)
	}

	var headerSection *slack.SectionBlock
	var fieldsSection *slack.SectionBlock

	if r.Status == Approved {
		err := conditionalBindIAMPolicy(ctx, r.Member, "organizations/6487630834", "organizations/6487630834/roles/hub_on_call_elevated")
		if err != nil {
			return fmt.Errorf("Unable to set IAM policy: %v", err)
		}
	}

	headerText := slack.NewTextBlockObject("mrkdwn", fmt.Sprint(r.Status.ApprovalText()), false, false)
	headerSection = slack.NewSectionBlock(headerText, nil, nil)
	//text = fmt.Sprintf("User: %s\n When: %s\n Reason: %s\n  Approver: %s\n The role %s has been granted for 1 hour.", user, when, reason, payload.User.Name, role)
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", r.Member), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", r.Role), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", r.Timestamp), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", r.Reason), false, false)
	approverField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*%s:*\n%s", r.Status.String(), r.Approver), false, false)

	log.Infof("[AUDIT] Requestor: %s, Role: %s, When: %s, Reason: %s, %s: %s", r.Member, r.Role, r.Timestamp, r.Reason, r.Status.String(), r.Approver)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, nameField)
	fieldSlice = append(fieldSlice, typeField)
	fieldSlice = append(fieldSlice, whenField)
	fieldSlice = append(fieldSlice, reasonField)
	fieldSlice = append(fieldSlice, approverField)

	fieldsSection = slack.NewSectionBlock(nil, fieldSlice, nil)
	msg := slack.NewBlockMessage(
		headerSection,
		fieldsSection,
	)
	msg.ResponseType = "in_channel"
	msg.ReplaceOriginal = true

	b, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		return err
	}
	resp, err := http.Post(message.ResponseURL,
		"application/json", bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func gcpEscalateIAM(w http.ResponseWriter, s slack.SlashCommand) {
	log.Debug("SlashCommand Escalate")

	// Header Section
	headerText := slack.NewTextBlockObject("mrkdwn", "There is a new authentication request to escalate GCP privileges", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	profile, err := api.GetUserProfile(s.UserID, true)
	if err != nil {
		log.Errorf("Unable to get user info from slack API: %v \n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	r := &EscalationRequest{
		Member:    member(strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)),
		Role:      "organizations/6487630834/roles/hub_on_call_elevated",
		Resource:  "organizations/6487630834",
		Reason:    s.Text,
		Timestamp: time.Now().Format("Mon Jan 2 15:04:05 MST 2006"),
	}

	if !strings.HasSuffix(string(r.Member), "@pachyderm.io") {
		log.Errorf("Unauthorized User, not from pachyderm.io: %v \n", r.Member)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = r.GetGroupMembership()
	if err != nil {
		log.Errorf("Unable to get group membership for user: %v \n", r.Member)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !r.Authorize(DefinedPolicy) {
		log.Errorf("Unauthorized User, not in the list of approved users: %v \n", r.Member)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Fields
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", r.Member), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", r.Role), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", r.Timestamp), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", r.Reason), false, false)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, nameField)
	fieldSlice = append(fieldSlice, typeField)
	fieldSlice = append(fieldSlice, whenField)
	fieldSlice = append(fieldSlice, reasonField)

	fieldsSection := slack.NewSectionBlock(nil, fieldSlice, nil)

	// Approve and Deny Buttons
	approveBtnTxt := slack.NewTextBlockObject("plain_text", "Approve", false, false)
	approveBtn := slack.NewButtonBlockElement("id1234", fmt.Sprintf("APPROVAL,0,%s,%s,%s,%s", r.Member, r.Role, r.Timestamp, r.Reason), approveBtnTxt)
	approveBtn.WithStyle("danger")

	denyBtnTxt := slack.NewTextBlockObject("plain_text", "Deny", false, false)
	denyBtn := slack.NewButtonBlockElement("id123", fmt.Sprintf("APPROVAL,1,%s,%s,%s,%s", r.Member, r.Role, r.Timestamp, r.Reason), denyBtnTxt)

	actionBlock := slack.NewActionBlock("", approveBtn, denyBtn)

	msg := slack.NewBlockMessage(
		headerSection,
		fieldsSection,
		actionBlock,
	)

	msg.ResponseType = "in_channel"
	b, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(b)
	if err != nil {
		log.Errorf("Unable to send escalation request to slack: %v \n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

// Attaches specific iam roles to a given user conditionally.
// Notably, this policy overwrites any existing policies.
// If you do not append your policy changes to an existing policy,
// it is very easy to get the gcp organization into a bad state.
// Please take a look at the comment in the critical section before making changes
func conditionalBindIAMPolicy(ctx context.Context, username member, orgId, IAMRole string) error {
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
		existingPolicy, err := cloudResourceManagerService.Organizations.GetIamPolicy(orgId, getIamPolicyRequest).Context(ctx).Do()
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
			return fmt.Errorf("Error: No existing policy was found for the GCP Organization")
		}
		existingPolicy.Bindings = append(existingPolicy.Bindings, binding)
		// In order to use conditional IAM, must set version to 3
		// See https://cloud.google.com/iam/docs/policies#versions
		existingPolicy.Version = 3
		setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: existingPolicy,
		}
		_, err = cloudResourceManagerService.Organizations.SetIamPolicy(orgId, setIamPolicyRequest).Context(ctx).Do()
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

func lookupCurrentOnCall() (map[member]bool, error) {
	oc, err := client.ListOnCalls(pagerduty.ListOnCallOptions{})
	if err != nil {
		return nil, err
	}
	users := map[member]bool{}
	for _, x := range oc.OnCalls {
		// This is the hardcoded Hub EscalationPolicyID
		if (x.EscalationLevel == 1 || x.EscalationLevel == 2) && x.EscalationPolicy.APIObject.ID == HubEscalationPolicyID {
			user, err := client.GetUser(x.User.APIObject.ID, pagerduty.GetUserOptions{})
			if err != nil {
				return nil, err
			}
			users[member(user.Email)] = true
		}
	}
	return users, nil
}