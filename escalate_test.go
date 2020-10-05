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
		er := NewTestER(&EscalationRequest{
			Member:    "test@pachyderm.io",
			Groups:    make(map[group]struct{}),
			Role:      "organizations/6487630834/roles/hub_on_call_elevated",
			Resource:  "organizations/6487630834",
			Reason:    "testing",
			Timestamp: "",
		})
		er.Groups["hub-on-call@pachyderm.io"] = struct{}{}
		got, err := er.handleGCPEscalateIAMRequestFromModal()
		if err != nil {
			t.Fatalf("handler failed: %s", err)
		}
		if got != nil {
			t.Errorf("got %v", got)
		}

		val, err := (json.Marshal(got))
		if err != nil {
			t.Fatalf("couldn't marshal too json: %s", err)
		}
		fmt.Println(val)
	})
}
