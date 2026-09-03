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

// LicenseStatus represents the state of a license.
type LicenseStatus string

const (
	StatusActive    LicenseStatus = "active"
	StatusExpired   LicenseStatus = "expired"
	StatusCancelled LicenseStatus = "cancelled"
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

// Claims are the JWT payload issued by this library.
type Claims struct {
	UserID    string  `json:"sub"`
	Email     string  `json:"email"`
	OrgID     string  `json:"org_id,omitempty"`
	LicenseID string  `json:"license_id"`
	Plan      Plan    `json:"plan"`
	Scopes    []Scope `json:"scopes"`
	DeviceID  string  `json:"device_id,omitempty"`
}

// TokenPair is returned to clients after successful authentication.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// DeviceFlowSession tracks a pending device authorization request.
type DeviceFlowSession struct {
	ID                string
	DeviceCode        string
	UserCode          string
	DeviceFingerprint string
	DeviceName        string
	Status            string // "pending", "complete", "expired"
	UserID            string // populated on completion
	ExpiresAt         time.Time
	CreatedAt         time.Time
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
