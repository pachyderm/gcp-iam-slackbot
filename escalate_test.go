package gcpiamslack

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/slack-go/slack"
)

func NewTestER(r *EscalationRequest) *ER {
	client := NewTestIntegrationClient()
	return &ER{Client: client, EscalationRequest: r}
}

func TestHandleGCPEscalateIAMFromModal(t *testing.T) {
	t.Run("HandleEscalate", func(t *testing.T) {
		blockString := `[{"type":"section","text":{"type":"mrkdwn","text":"There is a new authentication request to escalate GCP privileges"}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"}]},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Approve"},"action_id":"id1234","value":"{\"requestor\":\"test@pachyderm.io\",\"groups\":{\"hub-on-call@pachyderm.io\":{},\"testing@pachyderm.io\":{}},\"role\":\"organizations/6487630834/roles/hub_on_call_elevated\",\"resource\":\"organizations/6487630834\",\"reason\":\"testing\",\"approver\":\"\",\"timestamp\":\"\",\"status\":true,\"oncall\":false}","style":"danger"},{"type":"button","text":{"type":"plain_text","text":"Deny"},"action_id":"id123","value":"{\"requestor\":\"test@pachyderm.io\",\"groups\":{\"hub-on-call@pachyderm.io\":{},\"testing@pachyderm.io\":{}},\"role\":\"organizations/6487630834/roles/hub_on_call_elevated\",\"resource\":\"organizations/6487630834\",\"reason\":\"testing\",\"approver\":\"\",\"timestamp\":\"\",\"status\":false,\"oncall\":false}"}]}]`
		er := NewTestER(&EscalationRequest{
			Requestor: "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
		})
		er.Groups["hub-on-call@pachyderm.io"] = struct{}{}
		got, err := er.handleGCPEscalateIAMRequestFromModal()
		if err != nil {
			t.Fatalf("handler failed: %v", err)
		}
		var blocks *slack.Blocks
		err = json.Unmarshal([]byte(blockString), &blocks)
		if err != nil {
			t.Fatalf("couldn't marshal to json: %s", err)
		}
		want := blocks.BlockSet
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %v", diff)
		}
	})
}

func TestHandleApproval(t *testing.T) {
	tests := []struct {
		name     string
		input    *EscalationRequest
		expected []slack.Block
	}{
		{"Deny",
			&EscalationRequest{
				Requestor: "test@pachyderm.io",
				Groups:    map[group]struct{}{"hub-on-call@pachyderm.io": struct{}{}},
				Role:      "organizations/6487630834/roles/hub_on_call_elevated",
				Resource:  "organizations/6487630834",
				Reason:    "testing",
				Timestamp: "",
				Approver:  "test-approver@pachyderm.io",
			},
			//`[{"type":"section","text":{"type":"mrkdwn","text":"The Request has been denied."}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"},{"type":"mrkdwn","text":"*Denier:*\ntest-approver@pachyderm.io"}]}]`,
			[]slack.Block{
				&slack.SectionBlock{Type: "section", Text: &slack.TextBlockObject{Type: "mrkdwn", Text: "The Request has been denied."}},
				&slack.SectionBlock{
					Type:    "section",
					Text:    nil,
					BlockID: "",
					Fields: []*slack.TextBlockObject{
						&slack.TextBlockObject{
							Type:     "mrkdwn",
							Text:     "*User:*\ntest@pachyderm.io",
							Emoji:    false,
							Verbatim: false,
						},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*When:*\n"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Reason:*\ntesting"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Denier:*\ntest-approver@pachyderm.io"},
					},
					Accessory: nil,
				},
			},
		},
		{"Approve", &EscalationRequest{
			Requestor: "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
			Approver:  "test-approver@pachyderm.io",
			Status:    Approved,
		},
			// `[{"type":"section","text":{"type":"mrkdwn","text":"Approved. The role has been granted for 1 hour."}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@pachyderm.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},{"type":"mrkdwn","text":"*When:*\n"},{"type":"mrkdwn","text":"*Reason:*\ntesting"},{"type":"mrkdwn","text":"*Approver:*\ntest-approver@pachyderm.io"}]}]`,
			[]slack.Block{
				&slack.SectionBlock{Type: "section", Text: &slack.TextBlockObject{Type: "mrkdwn", Text: "Approved. The role has been granted for 1 hour."}},
				&slack.SectionBlock{
					Type:    "section",
					Text:    nil,
					BlockID: "",
					Fields: []*slack.TextBlockObject{
						&slack.TextBlockObject{
							Type:     "mrkdwn",
							Text:     "*User:*\ntest@pachyderm.io",
							Emoji:    false,
							Verbatim: false,
						},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Role:*\norganizations/6487630834/roles/hub_on_call_elevated"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*When:*\n"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Reason:*\ntesting"},
						&slack.TextBlockObject{Type: "mrkdwn", Text: "*Approver:*\ntest-approver@pachyderm.io"},
					},
					Accessory: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			er := NewTestER(tt.input)
			got, err := er.handleApproval()
			if err != nil {
				t.Errorf("handler failed: %v", err)
			}
			if diff := cmp.Diff(got, tt.expected); diff != "" {
				t.Errorf("diff: %v", diff)
			}
		})
	}
}
