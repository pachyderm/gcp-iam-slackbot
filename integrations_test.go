package gcpiamslack

import (
	"context"
	"testing"
)

type TestIntegrationClient struct{}

func NewTestIntegrationClient() *TestIntegrationClient {
	return &TestIntegrationClient{}
}

func (i *TestIntegrationClient) getGroupMembership(r *EscalationRequest) error {
	r.Groups[group("testing@pachyderm.io")] = struct{}{}
	return nil
}

func (i *TestIntegrationClient) conditionalBindIAMPolicy(ctx context.Context, r *EscalationRequest) error {
	return nil
}

func (i *TestIntegrationClient) lookupCurrentOnCall(r *EscalationRequest) bool {
	return member("test-user@pachyderm.io") == r.Member
}

// This doesn't use any pagerduty credentials because it's testing a failing lookup
// should not be blocking behavior
func TestLookupCurrentOnCall(t *testing.T) {
	t.Run("ListOptions", func(t *testing.T) {
		r := &EscalationRequest{Member: "test@example.com"}
		i := NewIntegrationClient()
		got := i.lookupCurrentOnCall(r)
		want := false
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}
