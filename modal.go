package gcpiamslack

import (
	"github.com/slack-go/slack"
)

func generateModalRequest() slack.ModalViewRequest {
	_, roles, resources := ListOptions(DefinedPolicy)
	//_ = createOptionBlockObjects(groups)
	roleOpts := createOptionBlockObjects(roles)
	resourceOpts := createOptionBlockObjects(resources)

	// Create a ModalViewRequest with a header and two inputs
	titleText := slack.NewTextBlockObject("plain_text", "IAM Escalation Request", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "Close", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "Submit", false, false)

	headerText := slack.NewTextBlockObject("mrkdwn", "Please fill in the following info", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	reasonText := slack.NewTextBlockObject("plain_text", "Reason", false, false)
	reasonPlaceholder := slack.NewTextBlockObject("plain_text", "Enter the reason for the request", false, false)
	reasonElement := slack.NewPlainTextInputBlockElement(reasonPlaceholder, "reason")
	reasonBlock := slack.NewInputBlock("GCP_Reason", reasonText, reasonElement)

	roleText := slack.NewTextBlockObject(slack.PlainTextType, "List of Roles", false, false)
	roleOption := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, nil, "role", roleOpts...)
	roleBlock := slack.NewInputBlock("gcp_role", roleText, roleOption)

	resourceText := slack.NewTextBlockObject(slack.PlainTextType, "List of Resources", false, false)
	resourceOption := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, nil, "resource", resourceOpts...)
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

func createOptionBlockObjects(options map[string]struct{}) []*slack.OptionBlockObject {
	optionBlockObjects := make([]*slack.OptionBlockObject, 0, len(options))
	for o := range options {
		optionText := slack.NewTextBlockObject(slack.PlainTextType, o, false, false)
		optionBlockObjects = append(optionBlockObjects, slack.NewOptionBlockObject(o, optionText))
	}
	return optionBlockObjects
}
