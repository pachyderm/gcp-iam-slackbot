package gcpiamslack

import (
	"context"
	"fmt"
	"log"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

type approval int

const (
	Approved approval = iota
	Denied
)

func (a approval) String() string {
	return [...]string{"Approver", "Denier"}[a]
}

func (a approval) ApprovalText() string {
	return [...]string{"Approved. The role has been granted for 1 hour.", "The Request has been denied."}[a]
}

type group string

type role string

type resource string

type member string

type ACL struct {
	Groups    map[group]struct{}
	Roles     map[role]struct{}
	Resources map[resource]struct{}
	// ApprovalGroup map[group]struct{}
}

type EscalationRequest struct {
	Member    member
	Groups    map[group]struct{}
	Role      role
	Resource  resource
	Reason    string
	Approver  string
	Timestamp string
	Status    approval
}

func (r *EscalationRequest) GetGroupMembership() error {
	//TODO: Get group membership
	ctx := context.Background()
	//
	srv, err := admin.NewService(ctx, option.WithScopes("https://www.googleapis.com/auth/admin.directory.group.readonly"))
	if err != nil {
		log.Fatalf("Unable to retrieve directory Client %v", err)
	}
	grpSrv := admin.NewGroupsService(srv)
	groups, err := grpSrv.List().UserKey("sean@pachyderm.io").Do()
	if err != nil {
		fmt.Println(err)
	}
	log.Warnf("Groups: %s", groups)
	r.Groups["pd-current-oncall"] = struct{}{}
	return nil
}

func (r *EscalationRequest) Authorize(policy *[]ACL) bool {
	for _, p := range *policy {
		for g, _ := range r.Groups {
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
