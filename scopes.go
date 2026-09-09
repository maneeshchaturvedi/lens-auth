package auth

// PlanScopes defines the scopes granted to each plan.
// This is the single source of truth for what each tier can access.
var PlanScopes = map[Plan][]Scope{
	PlanFree: {
		ScopeDashboardRead,
		ScopeCLI,
	},
	PlanPro: {
		ScopeDashboardRead,
		ScopeDashboardWrite,
		ScopeCLI,
		ScopeMCP,
	},
	PlanTeam: {
		ScopeDashboardRead,
		ScopeDashboardWrite,
		ScopeCLI,
		ScopeMCP,
	},
}

// ScopesForPlan returns the scopes granted to a plan.
func ScopesForPlan(p Plan) []Scope {
	scopes, ok := PlanScopes[p]
	if !ok {
		return nil
	}
	cp := make([]Scope, len(scopes))
	copy(cp, scopes)
	return cp
}
