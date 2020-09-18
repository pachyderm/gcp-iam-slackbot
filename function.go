package gcpiamslack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

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

	actionInfo := strings.Split(message.ActionCallback.BlockActions[0].Value, ",")
	switch actionInfo[0] {
	case "APPROVAL":
		err := handleApproval(message)
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
