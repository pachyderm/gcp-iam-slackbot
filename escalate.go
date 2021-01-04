package gcpiamslack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

type EscalationRequest struct {
	Requestor requestor          `json:"requestor"`
	Groups    map[group]struct{} `json:"groups"`
	Role      role               `json:"role"`
	Resource  resource           `json:"resource"`
	Reason    string             `json:"reason"`
	Approver  string             `json:"approver"`
	Timestamp string             `json:"timestamp"`
	Status    approval           `json:"status"`
	Oncall    bool               `json:"oncall"`
}

type Client interface {
	lookupCurrentOnCall(r *EscalationRequest) bool
	conditionalBindIAMPolicy(ctx context.Context, r *EscalationRequest) error
	getGroupMembership(r *EscalationRequest) error
}

type ER struct {
	*EscalationRequest
	Client Client `json:"client"`
}

func NewER(r *EscalationRequest) *ER {
	client := NewIntegrationClient()
	return &ER{Client: client, EscalationRequest: r}
}

func (er *ER) handleGCPEscalateIAMRequestFromModal() ([]slack.Block, error) {
	log.Debug("slash command escalate")

	if !strings.HasSuffix(string(er.Requestor), "@pachyderm.io") {
		return nil, fmt.Errorf("unauthorized user, not from pachyderm.io: %v", er.Requestor)

	}

	err := er.Client.getGroupMembership(er.EscalationRequest)
	if err != nil {
		return nil, fmt.Errorf("can't get group membership for user: %v", er.Requestor)
	}
	er.Oncall = er.Client.lookupCurrentOnCall(er.EscalationRequest)

	if !EscalationPolicy.Authorize(er.EscalationRequest) {
		return nil, fmt.Errorf("unauthorized: %v. Please double check it's a valid role and resource combination", er.Requestor)
	}

	msg := generateSlackEscalationRequestMessageFromModal(er.EscalationRequest)
	return msg, nil
}

func (er *ER) handleApproval() ([]slack.Block, error) {
	ctx := context.Background()

	if !strings.HasSuffix(er.Approver, "@pachyderm.io") {
		return nil, fmt.Errorf("unauthorized user, not from pachyderm.io: %v", er.Approver)
	}

	log.Infof("[AUDIT] Requestor: %s, Role: %s, Resource: %s, When: %s, Reason: %s, %s: %s", er.Requestor,
		er.Role, er.Resource, er.Timestamp, er.Reason, er.Status.String(), er.Approver)

	if er.Status == Approved {
		if !er.Oncall && string(er.Requestor) == er.Approver {
			return nil, fmt.Errorf("unauthorized, approver cannot be requester: %v", er.Approver)
		}
		err := er.Client.conditionalBindIAMPolicy(ctx, er.EscalationRequest)
		if err != nil {
			return nil, fmt.Errorf("couldn't set IAM policy: %v", err)
		}
	}

	blocks := generateSlackEscalationResponseMessage(er.EscalationRequest)
	return blocks, nil
}

func parseEscalationRequestFromApproval(message slack.InteractionCallback) (*EscalationRequest, error) {
	var r *EscalationRequest
	if err := json.Unmarshal([]byte(message.ActionCallback.BlockActions[0].Value), &r); err != nil {
		return nil, fmt.Errorf("can't unmarshal block action: %v", err)
	}
	approverProfile, err := api.GetUserProfile(message.User.ID, true)
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}
	r.Approver = strings.Replace(approverProfile.Email, "@pachyderm.com", "@pachyderm.io", 1)
	return r, nil
}

func parseEscalationRequestFromModal(message slack.InteractionCallback) (*EscalationRequest, error) {
	profile, err := api.GetUserProfile(message.User.ID, true)
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}
	requestor := requestor(strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1))

	reason := message.View.State.Values["gcp_reason"]["reasonz"].Value
	role := role(message.View.State.Values["gcp_role"]["rolez"].SelectedOption.Value)
	resource := resource(message.View.State.Values["gcp_resource"]["resourcez"].SelectedOption.Value)

	r := &EscalationRequest{
		Requestor: requestor,
		Groups:    make(map[group]struct{}),
		Role:      role,
		Resource:  resource,
		Reason:    reason,
		Timestamp: time.Now().Format(time.RFC822),
	}
	return r, nil
}
