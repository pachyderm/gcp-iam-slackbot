package gcpiamslack

import (
	"reflect"
	"testing"
)

var TestPolicy = &Policy{
	Policy: []ACL{
		ACL{
			Groups: map[group]struct{}{
				"hub-on-call@pachyderm.io": struct{}{},
			},
			Roles: map[role]struct{}{
				"organizations/6487630834/roles/hub_on_call_elevated": struct{}{},
			},
			Resources: map[resource]struct{}{
				"organizations/6487630834": struct{}{},
			},
		},
		ACL{
			Groups: map[group]struct{}{
				"test-group-1": struct{}{},
				"test-group-2": struct{}{},
				"test-group-3": struct{}{},
			},
			Roles: map[role]struct{}{
				"test-role-1": struct{}{},
				"test-role-2": struct{}{},
				"test-role-3": struct{}{},
			},
			Resources: map[resource]struct{}{
				"test-resource-1": struct{}{},
				"test-resource-2": struct{}{},
				"test-resource-3": struct{}{},
			},
		},
		ACL{
			Groups: map[group]struct{}{
				"test-group-4": struct{}{},
				"test-group-5": struct{}{},
				"test-group-6": struct{}{},
			},
			Roles: map[role]struct{}{
				"test-role-4": struct{}{},
			},
			Resources: map[resource]struct{}{
				"test-resource-4": struct{}{},
			},
		},
		ACL{
			Groups: map[group]struct{}{
				"test-group-4": struct{}{},
			},
			Roles: map[role]struct{}{
				"test-role-4": struct{}{},
				"test-role-5": struct{}{},
				"test-role-6": struct{}{},
			},
			Resources: map[resource]struct{}{
				"test-resource-4": struct{}{},
			},
		},
		ACL{
			Groups: map[group]struct{}{
				"test-group-4": struct{}{},
			},
			Roles: map[role]struct{}{
				"test-role-4": struct{}{},
			},
			Resources: map[resource]struct{}{
				"test-resource-4": struct{}{},
				"test-resource-5": struct{}{},
				"test-resource-6": struct{}{},
			},
		},
	},
}

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name     string
		input    *EscalationRequest
		expected bool
	}{
		{"test hub", &EscalationRequest{
			Groups:   map[group]struct{}{"hub-on-call@pachyderm.io": struct{}{}},
			Role:     "organizations/6487630834/roles/hub_on_call_elevated",
			Resource: "organizations/6487630834",
		}, true},
		{"test 1-2-3", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-1": struct{}{}},
			Role:     "test-role-2",
			Resource: "test-resource-3",
		}, true},
		{"test 3-2-1", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-3": struct{}{}},
			Role:     "test-role-2",
			Resource: "test-resource-1",
		}, true},
		{"test 4-4-4", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-4": struct{}{}},
			Role:     "test-role-4",
			Resource: "test-resource-4",
		}, true},
		{"test 5-4-4", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-5": struct{}{}},
			Role:     "test-role-4",
			Resource: "test-resource-4",
		}, true},
		{"test 4-5-6", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-4": struct{}{}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
		{"test 5-5-6", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-5": struct{}{}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
		{"test 6-5-4", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-3": struct{}{}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
		{"test 4-5-4", &EscalationRequest{
			Groups:   map[group]struct{}{"test-group-3": struct{}{}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := TestPolicy.Authorize(tt.input)
			if b != tt.expected {
				t.Errorf("got %v, want %v", b, tt.expected)
			}
		})
	}
}
func TestListOptions(t *testing.T) {
	t.Run("ListOptions", func(t *testing.T) {
		groups, roles, resources := TestPolicy.ListOptions()

		wantedGroups := map[group]struct{}{"hub-on-call@pachyderm.io": struct{}{}, "test-group-1": struct{}{}, "test-group-2": struct{}{}, "test-group-3": struct{}{}, "test-group-4": struct{}{}, "test-group-5": struct{}{}, "test-group-6": struct{}{}}
		wantedRoles := map[role]struct{}{"hub-on-call@pachyderm.io": struct{}{}, "test-role-1": struct{}{}, "test-role-2": struct{}{}, "test-role-3": struct{}{}, "test-role-4": struct{}{}, "test-role-5": struct{}{}, "test-role-6": struct{}{}}
		wantedResources := map[resource]struct{}{"hub-on-call@pachyderm.io": struct{}{}, "test-resource-1": struct{}{}, "test-resource-2": struct{}{}, "test-resource-3": struct{}{}, "test-resource-4": struct{}{}, "test-resource-5": struct{}{}, "test-resource-6": struct{}{}}

		if reflect.DeepEqual(wantedGroups, groups) {
			t.Errorf("got %v, want %v", groups, wantedGroups)
		}
		if reflect.DeepEqual(wantedRoles, roles) {
			t.Errorf("got %v, want %v", roles, wantedRoles)
		}
		if reflect.DeepEqual(wantedResources, resources) {
			t.Errorf("got %v, want %v", resources, wantedResources)
		}

	})
}
