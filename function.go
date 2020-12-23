package gcpiamslack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"

	"github.com/slack-go/slack"
)

const HubEscalationPolicyID = "PJVVTQR"

var signingSecret string
var client *pagerduty.Client
var api *slack.Client

func init() {
	signingSecret = os.Getenv("SLACK_SECRET")
	log.SetLevel(log.DebugLevel)
	api = slack.New(os.Getenv("SLACK_API_TOKEN"))
	client = pagerduty.NewClient(os.Getenv("PD_AUTH_TOKEN"))
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
			log.Error("sending echo response to slack")
			w.WriteHeader(http.StatusInternalServerError)
		}
	case "/escalate":
		modalRequest := generateModalRequest()
		_, err = api.OpenView(s.TriggerID, modalRequest)
		if err != nil {
			log.Errorf("opening view: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		log.Error("unsupported slash command")
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
		log.Errorf("invalid action response json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch message.Type {
	case "view_submission":
		viewSubmission(w, r, message)
	case "block_actions":
		blockActions(w, r, message)
	default:
		log.Errorf("unsupported action")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func verifyAuth(w http.ResponseWriter, r *http.Request) error {
	log.Debug("verifying auth")

	// Read request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("invalid request body: %v", err)
	}
	// Reset request body for other methods to act on
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	// Verify signing secret
	verifier, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	if _, err := verifier.Write(body); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	if err := verifier.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	return nil
}

func viewSubmission(w http.ResponseWriter, r *http.Request, message slack.InteractionCallback) {
	//send an empty acceptance response
	w.WriteHeader(http.StatusOK)
	escalationRequest, err := parseEscalationRequestFromModal(message)
	if err != nil {
		errMessage := fmt.Sprintf("counldn't parse escalation request: %v", err)
		log.Error(errMessage)
		blocks := textToBlock(errMessage)
		msg := slack.MsgOptionBlocks(blocks...)
		_, _, err = api.PostMessage("C01BPEQ024E", msg)
		if err != nil {
			log.Errorf("can't complete modal action: %v", err)
		}
		//w.WriteHeader(http.StatusInternalServerError)
	}

	er := NewER(escalationRequest)
	blocks, err := er.handleGCPEscalateIAMRequestFromModal()
	if err != nil {
		errMessage := fmt.Sprintf("counldn't handle escalation request: %v", err)
		log.Error(errMessage)
		blocks := textToBlock(errMessage)
		msg := slack.MsgOptionBlocks(blocks...)
		_, _, err = api.PostMessage("C01BPEQ024E", msg)
		if err != nil {
			log.Errorf("can't complete modal action: %v", err)
		}
		//w.WriteHeader(http.StatusInternalServerError)
	}
	msg := slack.MsgOptionBlocks(blocks...)
	//https://pachyderm.slack.com/archives/C01BPEQ024E
	_, _, err = api.PostMessage("C01BPEQ024E", msg)
	if err != nil {
		log.Errorf("can't complete modal action: %v", err)
	}
}

func blockActions(w http.ResponseWriter, r *http.Request, message slack.InteractionCallback) {
	escalationRequest, err := parseEscalationRequestFromApproval(message)
	if err != nil {
		errMessage := fmt.Sprintf("couldn't parse approval: %v", err)
		log.Error(errMessage)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	er := NewER(escalationRequest)
	blocks, err := er.handleApproval()
	if err != nil {
		errMessage := fmt.Sprintf("couldn't handle approval: %v", err)
		log.Error(errMessage)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	msg := slack.NewBlockMessage(blocks...)
	msg.ResponseType = "in_channel"
	msg.ReplaceOriginal = true
	b, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		log.Errorf("marshalling json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp, err := http.Post(message.ResponseURL, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Errorf("sending http request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
}
