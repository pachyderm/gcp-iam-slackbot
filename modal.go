package gcpiamslack

import (
	"github.com/slack-go/slack"
)

func generateModalRequest() slack.ModalViewRequest {
	groups, roles, resources := ListOptions(DefinedPolicy)

	// Create a ModalViewRequest with a header and two inputs
	titleText := slack.NewTextBlockObject("plain_text", "IAM Escalation Request", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "Close", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "Submit", false, false)

	headerText := slack.NewTextBlockObject("mrkdwn", "Please fill in the following info", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	resourceText := slack.NewTextBlockObject("plain_text", "Resource", false, false)
	resourcePlaceholder := slack.NewTextBlockObject("plain_text", "Enter the resource ID", false, false)
	resourceElement := slack.NewPlainTextInputBlockElement(resourcePlaceholder, "resource")
	resource := slack.NewInputBlock("GCP_Resource", resourceText, resourceElement)

	roleText := slack.NewTextBlockObject("plain_text", "Role", false, false)
	rolePlaceholder := slack.NewTextBlockObject("plain_text", "Enter the role", false, false)
	roleElement := slack.NewPlainTextInputBlockElement(rolePlaceholder, "role")
	role := slack.NewInputBlock("GCP_Role", roleText, roleElement)

	reasonText := slack.NewTextBlockObject("plain_text", "Reason", false, false)
	reasonPlaceholder := slack.NewTextBlockObject("plain_text", "Enter the reason for the request", false, false)
	reasonElement := slack.NewPlainTextInputBlockElement(reasonPlaceholder, "reason")
	reason := slack.NewInputBlock("GCP_Reason", reasonText, reasonElement)

	// Provide a static list of users to choose from, those provided now are just made up user IDs
	// Get user IDs by right clicking on them in Slack, select "Copy link", and inspect the last part of the link
	// The user ID should start with "U" followed by 8 random characters
	memberOptions := createOptionBlockObjects([]string{"testing-1-2-3", "4-5-6", "7-8-9"})
	inviteeText := slack.NewTextBlockObject(slack.PlainTextType, "Invitee from static list", false, false)
	inviteeOption := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, nil, "invitee", memberOptions...)
	inviteeBlock := slack.NewInputBlock("invitee", inviteeText, inviteeOption)

	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			headerSection,
			resource,
			role,
			reason,
			inviteeBlock,
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
	for _, o := range options {
		optionText := slack.NewTextBlockObject(slack.PlainTextType, o, false, false)
		optionBlockObjects = append(optionBlockObjects, slack.NewOptionBlockObject(o, optionText))
	}
	return optionBlockObjects
}
