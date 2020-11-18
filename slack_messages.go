package gcpiamslack

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

func generateModalRequest() slack.ModalViewRequest {
	_, roles, resources := EscalationPolicy.ListOptions()
	//_ = createOptionBlockObjects(groups)
	roleOpts := createOptionBlockObjects(roles)
	resourceOpts := createOptionBlockObjects(resources)

	titleText := slack.NewTextBlockObject("plain_text", "IAM Escalation Request", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "Close", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "Submit", false, false)

	headerText := slack.NewTextBlockObject("mrkdwn", "Please fill in the following info", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	reasonText := slack.NewTextBlockObject("plain_text", "Reason", false, false)
	reasonPlaceholder := slack.NewTextBlockObject("plain_text", "Enter the reason for the request", false, false)
	reasonElement := slack.NewPlainTextInputBlockElement(reasonPlaceholder, "reasonz")
	reasonBlock := slack.NewInputBlock("gcp_reason", reasonText, reasonElement)

	roleText := slack.NewTextBlockObject(slack.PlainTextType, "List of Roles", false, false)
	roleOption := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, nil, "rolez", roleOpts...)
	roleBlock := slack.NewInputBlock("gcp_role", roleText, roleOption)

	resourceText := slack.NewTextBlockObject(slack.PlainTextType, "List of Resources", false, false)
	resourceOption := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, nil, "resourcez", resourceOpts...)
	resourceBlock := slack.NewInputBlock("gcp_resource", resourceText, resourceOption)

	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			headerSection,
			reasonBlock,
			resourceBlock,
			roleBlock,
		},
	}

	var modalRequest slack.ModalViewRequest
	modalRequest.Type = slack.ViewType("modal")
	modalRequest.Title = titleText
	modalRequest.Close = closeText
	modalRequest.Submit = submitText
	modalRequest.Blocks = blocks
	return modalRequest
}

func generateSlackEscalationRequestMessageFromModal(r *EscalationRequest) []slack.Block {

	// Header Section
	headerText := slack.NewTextBlockObject("mrkdwn", "There is a new authentication request to escalate GCP privileges", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)
	// Fields
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", r.Requestor), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", r.Role), false, false)
	resourceField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Resource:*\n%s", r.Resource), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", r.Timestamp), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", r.Reason), false, false)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, nameField)
	fieldSlice = append(fieldSlice, typeField)
	fieldSlice = append(fieldSlice, resourceField)
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

	msg := []slack.Block{
		headerSection,
		fieldsSection,
		actionBlock,
	}
	return msg
}

func generateSlackEscalationResponseMessage(r *EscalationRequest) []slack.Block {
	var headerSection *slack.SectionBlock
	var fieldsSection *slack.SectionBlock

	headerText := slack.NewTextBlockObject("mrkdwn", fmt.Sprint(r.Status.ApprovalText()), false, false)
	headerSection = slack.NewSectionBlock(headerText, nil, nil)
	//text = fmt.Sprintf("User: %s\n When: %s\n Reason: %s\n  Approver: %s\n The role %s has been granted for 1 hour.", user, when, reason, payload.User.Name, role)
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", r.Requestor), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", r.Role), false, false)
	resourceField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Resource:*\n%s", r.Resource), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", r.Timestamp), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", r.Reason), false, false)
	approverField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*%s:*\n%s", r.Status.String(), r.Approver), false, false)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, nameField)
	fieldSlice = append(fieldSlice, typeField)
	fieldSlice = append(fieldSlice, resourceField)
	fieldSlice = append(fieldSlice, whenField)
	fieldSlice = append(fieldSlice, reasonField)
	fieldSlice = append(fieldSlice, approverField)

	fieldsSection = slack.NewSectionBlock(nil, fieldSlice, nil)
	blocks := []slack.Block{
		headerSection,
		fieldsSection,
	}
	return blocks

}

func createOptionBlockObjects(options map[string]struct{}) []*slack.OptionBlockObject {
	optionBlockObjects := make([]*slack.OptionBlockObject, 0, len(options))
	for o := range options {
		optionText := slack.NewTextBlockObject(slack.PlainTextType, o, false, false)
		optionBlockObjects = append(optionBlockObjects, slack.NewOptionBlockObject(o, optionText))
	}
	return optionBlockObjects
}
