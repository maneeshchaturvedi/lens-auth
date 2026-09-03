package auth

import (
	"slices"
	"time"
)

// Plan represents a license tier.
type Plan string

const (
	PlanFree Plan = "free"
	PlanPro  Plan = "pro"
	PlanTeam Plan = "team"
)

// Scope represents a fine-grained permission.
type Scope string

const (
	ScopeDashboardRead  Scope = "dashboard:read"
	ScopeDashboardWrite Scope = "dashboard:write"
	ScopeCLI            Scope = "cli:access"
	ScopeMCP            Scope = "mcp:access"
)

// Identity is the resolved auth context for a request.
// Server components work with this — never with users, licenses, or orgs directly.
type Identity struct {
	UserID    string  `json:"user_id"`
	Email     string  `json:"email"`
	OrgID     string  `json:"org_id,omitempty"`
	LicenseID string  `json:"license_id"`
	Plan      Plan    `json:"plan"`
	Scopes    []Scope `json:"scopes"`
}

// HasScope checks whether this identity has a specific scope.
func (id *Identity) HasScope(s Scope) bool {
	return slices.Contains(id.Scopes, s)
}

// TokenResponse is returned to clients after successful authentication.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshToken is stored server-side for revocation support.
type RefreshToken struct {
	ID                string
	TokenHash         string
	UserID            string
	LicenseID         string
	DeviceFingerprint string
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
}
