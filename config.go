package gcpiamslack

// Without a policy defined all requests will be denied by default.
// Policies can only allow access to roles and resources
// No support for hierarchy
// No support for individual membership
// No support for wildcards
var EscalationPolicy = &Policy{
	Policy: []ACL{
		{
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
		{
			Groups: map[group]struct{}{
				"hub-on-call@pachyderm.io": struct{}{},
			},
			Roles: map[role]struct{}{
				"organizations/6487630834/roles/hub_on_call_elevated": struct{}{},
			},
			Resources: map[resource]struct{}{
				"projects/pachhub-prod": struct{}{},
			},
		},
		{
			Groups: map[group]struct{}{
				"prod-db-access@pachyderm.io": struct{}{},
			},
			Roles: map[role]struct{}{
				"roles/cloudsql.admin": struct{}{},
			},
			Resources: map[resource]struct{}{
				"projects/pachhub-prod": struct{}{},
			},
		},{
			Groups: map[group]struct{}{
				"hub-on-call-sudo@pachyderm.io": struct{}{},
			},
			Roles: map[role]struct{}{
				"organizations/6487630834/roles/hub_root": struct{}{},
			},
			Resources: map[resource]struct{}{
				"organizations/6487630834": struct{}{},
			},
		},
	},
}
