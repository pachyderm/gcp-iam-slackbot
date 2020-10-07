package gcpiamslack

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

type requestor string

type ACL struct {
	Groups    map[group]struct{}
	Roles     map[role]struct{}
	Resources map[resource]struct{}
}

type Policy struct {
	Policy []ACL
}

func (p *Policy) Authorize(r *EscalationRequest) bool {
	for _, pol := range p.Policy {
		for g := range r.Groups {
			if _, ok := pol.Groups[g]; !ok {
				continue
			}
			if _, ok := pol.Roles[r.Role]; !ok {
				continue
			}
			if _, ok := pol.Resources[r.Resource]; ok {
				return true
			}
		}
	}
	return false
}

//Returns deduplicated lists of groups, roles and resources
func (p *Policy) ListOptions() (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	groups := make(map[string]struct{})
	roles := make(map[string]struct{})
	resources := make(map[string]struct{})
	for _, pol := range p.Policy {
		for g := range pol.Groups {
			groups[string(g)] = struct{}{}
		}
		for rl := range pol.Roles {
			roles[string(rl)] = struct{}{}
		}
		for rsc := range pol.Resources {
			resources[string(rsc)] = struct{}{}
		}
	}
	return groups, roles, resources
}
