package gcpiamslack

import (
	"context"

	"git.sr.ht/~urandom/dwd"
	log "github.com/sirupsen/logrus"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

type approval bool

const (
	Approved approval = true
	Denied   approval = false
)

func (a approval) String() string {
	if a {
		return "Approver"
	}
	return "Denier"
}

func (a approval) ApprovalText() string {
	if a {
		return "Approved. The role has been granted for 1 hour."
	}
	return "The Request has been denied."
}

type group string

type role string

type resource string

type member string

type ACL struct {
	Groups    map[group]struct{}
	Roles     map[role]struct{}
	Resources map[resource]struct{}
}

type EscalationRequest struct {
	Member    member             `json:"member"`
	Groups    map[group]struct{} `json:"groups"`
	Role      role               `json:"role"`
	Resource  resource           `json:"resource"`
	Reason    string             `json:"reason"`
	Approver  string             `json:"approver"`
	Timestamp string             `json:"timestamp"`
	Status    approval           `json:"status"`
	Oncall    bool               `json:"oncall"`
}

func (r *EscalationRequest) GetGroupMembership() error {
	ctx := context.Background()
	// This is using a 3rd party lib because there is a long standing issue with
	// the interplay between gsuite's admin sdk needing account impersonation and
	// no 1st party support for that with existing GCP API's.

	// https://github.com/googleapis/google-api-go-client/issues/652
	// https://github.com/googleapis/google-api-go-client/issues/379
	ts := dwd.TokenSource(
		ctx,
		// User must be a GSuite admin.
		"jdoliner@pachyderm.io",
		admin.AdminDirectoryGroupReadonlyScope,
	)
	srv, err := admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Errorf("Unable to retrieve directory Client %v", err)
		return err
	}
	grpSrv := admin.NewGroupsService(srv)
	groups, err := grpSrv.List().Domain("pachyderm.io").UserKey(string(r.Member)).Do()
	if err != nil {
		log.Errorf("Can't retrieve groups from google: %v", err)
		return err
	}
	for _, g := range groups.Groups {
		r.Groups[group(g.Email)] = struct{}{}
	}
	return nil
}

func (r *EscalationRequest) Authorize(policy *[]ACL) bool {
	for _, p := range *policy {
		for g := range r.Groups {
			if _, ok := p.Groups[g]; !ok {
				continue
			}
			if _, ok := p.Roles[r.Role]; !ok {
				continue
			}
			if _, ok := p.Resources[r.Resource]; ok {
				return true
			}
		}
	}
	return false
}

//Returns deduplicated lists of groups, roles and resources
func ListOptions(policy *[]ACL) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	groups := make(map[string]struct{})
	roles := make(map[string]struct{})
	resources := make(map[string]struct{})
	for _, p := range *policy {
		for g := range p.Groups {
			groups[string(g)] = struct{}{}
		}
		for rl := range p.Roles {
			roles[string(rl)] = struct{}{}
		}
		for rsc := range p.Resources {
			resources[string(rsc)] = struct{}{}
		}
	}
	return groups, roles, resources
}
