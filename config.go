package gcpiamslack

// Without a policy defined all requests will be denied by default.
// Policies can only allow access to roles and resources
// No support for hierarchy
// No support for individual membership
// No support for wildcards
var DefinedPolicy = &[]ACL{
	ACL{
		Groups: map[group]struct{}{
			"pd-current-oncall":       struct{}{},
			"hub-oncall@pachyderm.io": struct{}{},
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
			"pd-current-oncall": struct{}{},
			"test@pachyderm.io": struct{}{},
		},
		Roles: map[role]struct{}{
			"organizations/6487630834/roles/hub_on_call_elevated": struct{}{},
		},
		Resources: map[resource]struct{}{
			"organizations/6487630834": struct{}{},
		},
	},
}
