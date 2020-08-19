package gcpiamslack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jpillora/backoff"
	"github.com/slack-go/slack"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

var signingSecret string
var api *slack.Client

func init() {
	signingSecret = os.Getenv("SLACK_SECRET")
	log.SetLevel(log.DebugLevel)
	api = slack.New(os.Getenv("SLACK_API_TOKEN"))
}

func SlashHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("SlashHandler")
	if err := verifyAuth(w, r); err != nil {
		log.Error(err)
		return
	}

	s, err := slack.SlashCommandParse(r)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch s.Command {
	case "/echo":
		log.Debug("SlashCommand Echo")
		params := &slack.Msg{Text: s.Text}
		b, err := json.Marshal(params)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(b)
		if err != nil {
			log.Error("Unable to send echo response to slack")
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/escalate":
		gcpEscalateIAM(w, s)
	default:
		log.Error("Unsupported Slash Command")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func ActionHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("ActionHandler")
	if err := verifyAuth(w, r); err != nil {
		log.Error(err)
		return
	}
	var message slack.InteractionCallback
	err := json.Unmarshal([]byte(r.FormValue("payload")), &message)
	if err != nil {
		log.Errorf("Could not parse action response JSON: %v \n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//userEmail := fmt.Sprintf("%s@pachyderm.io", payload.User.Name)

	actionInfo := strings.Split(message.ActionCallback.BlockActions[0].Value, ",")
	switch actionInfo[0] {
	case "APPROVAL":
		err := approval(message)
		if err != nil {
			log.Errorf("Unable to complete approval action: %v \n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		log.Errorf("Unsupported Action")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func verifyAuth(w http.ResponseWriter, r *http.Request) error {
	log.Debug("Verifying Auth")

	// Read request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("[ERROR] Fail to read request body: %v", err)
	}
	// Reset request body for other methods to act on
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	// Verify signing secret
	verifier, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Failed to verify SigningSecret: %v", err)
	}
	if _, err := verifier.Write(body); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("[ERROR] Fail to verify SigningSecret: %v", err)
	}
	if err := verifier.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Failed to verify SigningSecret: %v", err)
	}
	return nil
}

func approval(message slack.InteractionCallback) error {
	ctx := context.Background()
	actionInfo := strings.Split(message.ActionCallback.BlockActions[0].Value, ",")

	//actionType := actionInfo[0]
	approval := actionInfo[1]
	user := actionInfo[2]
	role := actionInfo[3]
	when := actionInfo[4]
	reason := actionInfo[5]

	log.Debugf("User: %s \n", user)

	var headerSection *slack.SectionBlock
	var fieldsSection *slack.SectionBlock

	approvalText := "The Request has been denied."
	approverText := "Denier"

	if approval == "APPROVED" {
		approvalText = "Approved. The role has been granted for 1 hour."
		approverText = "Approver"

		err := conditionalBindIAMPolicy(ctx, "organizations/6487630834", "sean@pachyderm.io", "roles/editor")
		if err != nil {
			return fmt.Errorf("[ERROR] Error retrieving IAM: %v", err)
		}
	}

	log.Debugf("APPROVER_ID: %s", message.User.ID)
	profile, err := api.GetUserProfile(message.User.ID, true)
	if err != nil {
		return fmt.Errorf("Unable to get user info from slack API: %v \n", err)

	}
	log.Debugf("APPROVER_EMAIL: %s", profile.Email)
	email := strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)
	if !strings.HasSuffix(email, "@pachyderm.io") {
		return fmt.Errorf("Unauthorized User, not from pachyderm.io: %v \n", email)
	}

	headerText := slack.NewTextBlockObject("mrkdwn", fmt.Sprint(approvalText), false, false)
	headerSection = slack.NewSectionBlock(headerText, nil, nil)
	//text = fmt.Sprintf("User: %s\n When: %s\n Reason: %s\n  Approver: %s\n The role %s has been granted for 1 hour.", user, when, reason, payload.User.Name, role)
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", user), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", role), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", when), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", reason), false, false)
	approverField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*%s:*\n%s", approverText, email), false, false)

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

	log.Debugf("USER_ID: %s", s.UserID)
	profile, err := api.GetUserProfile(s.UserID, true)
	if err != nil {
		log.Errorf("Unable to get user info from slack API: %v \n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Debugf("USER_EMAIL: %s", profile.Email)

	user := strings.Replace(profile.Email, "@pachyderm.com", "@pachyderm.io", 1)
	role := "Hub On Call Elevated"
	when := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")
	reason := s.Text

	if !strings.HasSuffix(user, "@pachyderm.io") {
		log.Errorf("Unauthorized User, not from pachyderm.io: %v \n", user)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fields
	nameField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*User:*\n%s", user), false, false)
	typeField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Role:*\n%s", role), false, false)
	whenField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*When:*\n%s", when), false, false)
	reasonField := slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Reason:*\n%s", reason), false, false)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, nameField)
	fieldSlice = append(fieldSlice, typeField)
	fieldSlice = append(fieldSlice, whenField)
	fieldSlice = append(fieldSlice, reasonField)

	fieldsSection := slack.NewSectionBlock(nil, fieldSlice, nil)

	// Approve and Deny Buttons
	approveBtnTxt := slack.NewTextBlockObject("plain_text", "Approve", false, false)
	approveBtn := slack.NewButtonBlockElement("id1234", fmt.Sprintf("APPROVAL,APPROVED,%s,%s,%s,%s", user, role, when, reason), approveBtnTxt)
	approveBtn.WithStyle("danger")

	denyBtnTxt := slack.NewTextBlockObject("plain_text", "Deny", false, false)
	denyBtn := slack.NewButtonBlockElement("id123", fmt.Sprintf("APPROVAL,DENIED,%s,%s,%s,%s", user, role, when, reason), denyBtnTxt)

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
func conditionalBindIAMPolicy(ctx context.Context, orgId, username, IAMRole string) error {
	log.Debug("Getting IAM Policy")
	//c, err := google.DefaultClient(ctx, cloudresourcemanager.CloudPlatformScope)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//cloudResourceManagerService, err := cloudresourcemanager.New(c)

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize google cloudresourcemanager: %v", err)
	}

	//userEmail := []string{fmt.Sprintf("user:%s", username)}
	//binding := &cloudresourcemanager.Binding{
	//	Role:    IAMRole,
	//	Members: userEmail,
	//}
	getIamPolicyRequest := &cloudresourcemanager.GetIamPolicyRequest{}
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
		//fmt.Printf("Policy is: %s\n", existingPolicy)

		// Please use caution for this section!!
		// It is important that the existing policy is appeneded to.
		// If it is not, the new policy will overwrite the existing policy.
		// This will remove all existing permissions at the gcp org level!
		if existingPolicy == nil {
			return fmt.Errorf("Error: No existing policy was found for the GCP Organization")
		}
		//existingPolicy.Bindings = append(existingPolicy.Bindings, binding)
		//setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
		//	Policy: existingPolicy,
		//}
		//_, err = projectService.SetIamPolicy(projectId, setIamPolicyRequest).Context(ctx).Do()
		//if e, ok := err.(*googleapi.Error); ok {
		//	if e.Code == 409 {
		//		time.Sleep(d)
		//		continue
		//	}
		//}
		//if err != nil {
		//	return fmt.Errorf("failed to set iam policy: %v", err)
		//}
		return nil
	}
}
