package gcpiamslack

import (
	"encoding/json"
	"fmt"
	"testing"
)

func NewTestER(r *EscalationRequest) *ER {
	client := NewTestIntegrationClient()
	return &ER{Client: client, EscalationRequest: r}
}

func TestHandleGCPEscalateIAMFromModal(t *testing.T) {
	t.Run("ListOptions", func(t *testing.T) {
		want := `[{"type":"section","text":{"type":"mrkdwn","text":"There is a new authentication request to escalate GCP privileges"}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"}]},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Approve"},"action_id":"id1234","value":"{\"member\":\"test@pachyderm.io\",\"groups\":{\"hub-on-call@pachyderm.io\":{},\"testing@pachyderm.io\":{}},\"role\":\"organizations/6487630834/roles/hub_on_call_elevated\",\"resource\":\"organizations/6487630834\",\"reason\":\"testing\",\"approver\":\"\",\"timestamp\":\"\",\"status\":true,\"oncall\":false}","style":"danger"},{"type":"button","text":{"type":"plain_text","text":"Deny"},"action_id":"id123","value":"{\"member\":\"test@pachyderm.io\",\"groups\":{\"hub-on-call@pachyderm.io\":{},\"testing@pachyderm.io\":{}},\"role\":\"organizations/6487630834/roles/hub_on_call_elevated\",\"resource\":\"organizations/6487630834\",\"reason\":\"testing\",\"approver\":\"\",\"timestamp\":\"\",\"status\":false,\"oncall\":false}"}]}]`
		er := NewTestER(&EscalationRequest{
			Member:    "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
		})
		er.Groups["hub-on-call@pachyderm.io"] = struct{}{}
		val, err := er.handleGCPEscalateIAMRequestFromModal()
		if err != nil {
			t.Fatalf("handler failed: %s", err)
		}
		v, err := (json.Marshal(val))
		if err != nil {
			t.Fatalf("couldn't marshal too json: %s", err)
		}
		got := string(v)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestHandleApproval(t *testing.T) {
	t.Run("handleApproval - Deny", func(t *testing.T) {
		want := `[{"type":"section","text":{"type":"mrkdwn","text":"The Request has been denied."}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"},{"type":"mrkdwn","text":"*Denier:*\ntest-approver@pachyderm.io"}]}]`
		er := NewTestER(&EscalationRequest{
			Member:    "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
			Approver:  "test-approver@pachyderm.io",
		})
		er.Groups["hub-on-call@pachyderm.io"] = struct{}{}
		val, err := er.handleApproval()
		if err != nil {
			t.Fatalf("handler failed: %s", err)
		}
		v, err := (json.Marshal(val))
		if err != nil {
			t.Fatalf("couldn't marshal too json: %s", err)
		}
		got := string(v)
		if got != want {
			t.Errorf("got %v,\n want %v\n", got, want)
			fmt.Println("XXXXXXX")
		}
	})
	t.Run("handleApproval - Approve", func(t *testing.T) {
		want := `[{"type":"section","text":{"type":"mrkdwn","text":"Approved. The role has been granted for 1 hour."}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"},{"type":"mrkdwn","text":"*Approver:*\ntest-approver@pachyderm.io"}]}]`
		er := NewTestER(&EscalationRequest{
			Member:    "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
			Approver:  "test-approver@pachyderm.io",
			Status:    Approved,
		})
		er.Groups["hub-on-call@pachyderm.io"] = struct{}{}
		val, err := er.handleApproval()
		if err != nil {
			t.Fatalf("handler failed: %s", err)
		}
		v, err := (json.Marshal(val))
		if err != nil {
			t.Fatalf("couldn't marshal too json: %s", err)
		}
		got := string(v)
		if got != want {
			t.Errorf("got %v,\n want %v\n", got, want)
			fmt.Println("XXXXXXX")
		}
	})
}
