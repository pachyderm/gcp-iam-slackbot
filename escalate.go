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

func handleGCPEscalateIAMRequest(s slack.SlashCommand) (slack.Message, error) {
	log.Debug("SlashCommand Escalate")

	//profile, err := api.GetUserProfile(s.UserID, true)
	//if err != nil {
	//	log.Errorf("Unable to get user info from slack: %v", err)
	//	w.WriteHeader(http.StatusInternalServerError)
	//	return
	//}
	//
	//r := &EscalationRequest{
	//	Member:    member(strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)),
	//	Groups:    make(map[group]struct{}),
	//	Role:      "organizations/6487630834/roles/hub_on_call_elevated",
	//	Resource:  "organizations/6487630834",
	//	Reason:    s.Text,
	//	Timestamp: time.Now().Format(time.RFC822),
	//}

	r, err := parseInitialEscalationRequest(s)
	if err != nil {
		return slack.Message{}, fmt.Errorf("can't parse escalation request")
	}

	if !strings.HasSuffix(string(r.Member), "@pachyderm.io") {
		return slack.Message{}, fmt.Errorf("Unauthorized User, not from pachyderm.io: %v", r.Member)

	}

	err = r.GetGroupMembership()
	if err != nil {
		return slack.Message{}, fmt.Errorf("Unable to get group membership for user: %v", r.Member)
	}
	r.Oncall = lookupCurrentOnCall(r.Member)

	if !r.Authorize(DefinedPolicy) {
		return slack.Message{}, fmt.Errorf("Unauthorized User, not in the list of approved users: %v", r.Member)
	}

	msg := generateSlackEscalationRequestMessage(r)
	return msg, nil

}

func handleGCPEscalateIAMRequestFromModal(role role, resource resource, reason, requestor string) (slack.MsgOption, error) {
	log.Debug("SlashCommand Escalate")

	r, err := parseInitialEscalationRequestFromModal(role, resource, reason, requestor)
	if err != nil {
		return nil, fmt.Errorf("can't parse escalation request")
	}

	if !strings.HasSuffix(string(r.Member), "@pachyderm.io") {
		return nil, fmt.Errorf("Unauthorized User, not from pachyderm.io: %v", r.Member)

	}

	err = r.GetGroupMembership()
	if err != nil {
		return nil, fmt.Errorf("Unable to get group membership for user: %v", r.Member)
	}
	r.Oncall = lookupCurrentOnCall(r.Member)

	if !r.Authorize(DefinedPolicy) {
		return nil, fmt.Errorf("Unauthorized User, not in the list of approved users: %v", r.Member)
	}

	msg := generateSlackEscalationRequestMessageFromModal(r)
	return msg, nil

}
func handleApproval(message slack.InteractionCallback) (slack.Message, error) {
	//log.Debug(message)
	//b, err := json.MarshalIndent(message, "", "    ")
	//fmt.Printf("ssss: %s", b)
	//log.Debug(b)
	//if err != nil {
	//	return slack.Message{}, fmt.Errorf("Unable to marshal json: %v", err)
	//}
	ctx := context.Background()
	var r *EscalationRequest
	if err := json.Unmarshal([]byte(message.ActionCallback.BlockActions[0].Value), &r); err != nil {
		return slack.Message{}, fmt.Errorf("can't unmarshal json: %v", err)
	}
	//actionInfo := strings.Split(message.ActionCallback.BlockActions[0].Value, ",")
	//log.Debugf(message.ActionCallback.BlockActions[0].Value)
	//approvalStatus, err := strconv.ParseBool(actionInfo[1])
	//if err != nil {
	//	return slack.Message{}, fmt.Errorf("invalid approval status: %v", err)
	//}
	//onCall, err := strconv.ParseBool(actionInfo[6])
	//if err != nil {
	//	return slack.Message{}, fmt.Errorf("invalid oncall status: %v", err)
	//}

	//r := &EscalationRequest{
	//	Member:    member(actionInfo[2]),
	//	Role:      role(actionInfo[3]),
	//	Resource:  "organizations/6487630834",
	//	Reason:    actionInfo[5],
	//	Timestamp: actionInfo[4],
	//	Status:    approval(approvalStatus),
	//	Oncall:    onCall,
	//}

	approverProfile, err := api.GetUserProfile(message.User.ID, true)
	if err != nil {
		return slack.Message{}, fmt.Errorf("Unable to get user info from slack: %v", err)
	}
	r.Approver = strings.Replace(approverProfile.Email, "@pachyderm.com", "@pachyderm.io", 1)
	if !strings.HasSuffix(r.Approver, "@pachyderm.io") {
		return slack.Message{}, fmt.Errorf("Unauthorized User, not from pachyderm.io: %v", r.Approver)
	}

	if r.Status == Approved {
		if !r.Oncall && string(r.Member) == r.Approver {
			return slack.Message{}, fmt.Errorf("Unauthorized, approver cannot be requester: %v", r.Approver)
		}
		err := conditionalBindIAMPolicy(ctx, r.Member, r.Resource, "organizations/6487630834/roles/hub_on_call_elevated")
		if err != nil {
			return slack.Message{}, fmt.Errorf("Unable to set IAM policy: %v", err)
		}
	}

	msg := generateSlackEscalationResponseMessage(r)
	return msg, nil
}

func parseInitialEscalationRequest(s slack.SlashCommand) (*EscalationRequest, error) {
	profile, err := api.GetUserProfile(s.UserID, true)
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}

	return &EscalationRequest{
		Member:    member(strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)),
		Groups:    make(map[group]struct{}),
		Role:      "organizations/6487630834/roles/hub_on_call_elevated",
		Resource:  "organizations/6487630834",
		Reason:    s.Text,
		Timestamp: time.Now().Format(time.RFC822),
	}, nil
}

func parseInitialEscalationRequestFromModal(role role, resource resource, reason, requestor string) (*EscalationRequest, error) {
	profile, err := api.GetUserProfile(requestor, true)
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}

	return &EscalationRequest{
		Member:    member(strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)),
		Groups:    make(map[group]struct{}),
		Role:      role,
		Resource:  resource,
		Reason:    reason,
		Timestamp: time.Now().Format(time.RFC822),
	}, nil
}

func generateSlackEscalationRequestMessageFromModal(r *EscalationRequest) slack.MsgOption {

	// Header Section
	headerText := slack.NewTextBlockObject("mrkdwn", "There is a new authentication request to escalate GCP privileges", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)
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
	r.Status = Approved
	buttonPayloadApproval, err := json.Marshal(&r)
	if err != nil {
		log.Errorf("can't marshal json: %v", err)
	}
	//approveBtn := slack.NewButtonBlockElement("id1234", fmt.Sprintf("APPROVAL,true,%s,%s,%s,%s,%v", r.Member, r.Role, r.Timestamp, r.Reason, r.Oncall), approveBtnTxt)
	approveBtn := slack.NewButtonBlockElement("id1234", string(buttonPayloadApproval), approveBtnTxt)
	approveBtn.WithStyle("danger")

	denyBtnTxt := slack.NewTextBlockObject("plain_text", "Deny", false, false)
	r.Status = Denied
	buttonPayloadDenial, err := json.Marshal(&r)
	if err != nil {
		log.Errorf("can't marshal json: %v", err)
	}
	denyBtn := slack.NewButtonBlockElement("id123", string(buttonPayloadDenial), denyBtnTxt)

	actionBlock := slack.NewActionBlock("", approveBtn, denyBtn)

	msg := slack.MsgOptionBlocks(
		headerSection,
		fieldsSection,
		actionBlock,
	)
	//	msg.ResponseType = "in_channel"

	return msg
}

func generateSlackEscalationRequestMessage(r *EscalationRequest) slack.Message {

	// Header Section
	headerText := slack.NewTextBlockObject("mrkdwn", "There is a new authentication request to escalate GCP privileges", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)
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
	r.Status = Approved
	buttonPayloadApproval, err := json.Marshal(&r)
	if err != nil {
		log.Errorf("can't marshal json: %v", err)
	}
	//approveBtn := slack.NewButtonBlockElement("id1234", fmt.Sprintf("APPROVAL,true,%s,%s,%s,%s,%v", r.Member, r.Role, r.Timestamp, r.Reason, r.Oncall), approveBtnTxt)
	approveBtn := slack.NewButtonBlockElement("id1234", string(buttonPayloadApproval), approveBtnTxt)
	approveBtn.WithStyle("danger")

	denyBtnTxt := slack.NewTextBlockObject("plain_text", "Deny", false, false)
	r.Status = Denied
	buttonPayloadDenial, err := json.Marshal(&r)
	if err != nil {
		log.Errorf("can't marshal json: %v", err)
	}
	denyBtn := slack.NewButtonBlockElement("id123", string(buttonPayloadDenial), denyBtnTxt)

	actionBlock := slack.NewActionBlock("", approveBtn, denyBtn)

	msg := slack.NewBlockMessage(
		headerSection,
		fieldsSection,
		actionBlock,
	)
	msg.ResponseType = "in_channel"

	return msg
}

func generateSlackEscalationResponseMessage(r *EscalationRequest) slack.Message {
	var headerSection *slack.SectionBlock
	var fieldsSection *slack.SectionBlock

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
	return msg

}
