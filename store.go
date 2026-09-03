package auth

import "context"

// Store is the database interface the auth library needs.
// Since all services share one DB, this library provides the implementation (postgres.go).
type Store interface {
	// ResolveIdentity resolves the full identity chain for a user.
	// Today: user → license → plan → scopes.
	// Tomorrow: user → org → license → plan → scopes.
	// The implementation evolves; the interface stays stable.
	ResolveIdentity(ctx context.Context, userID string) (*Identity, error)

	// GetOrCreateUser finds or creates a user from a WorkOS identity.
	// Returns the internal user ID.
	GetOrCreateUser(ctx context.Context, workosID, email string) (string, error)

	// Device flow session management (DB-backed for multi-instance servers).
	CreateDeviceFlowSession(ctx context.Context, session *DeviceFlowSession) error
	GetDeviceFlowByDeviceCode(ctx context.Context, deviceCode string) (*DeviceFlowSession, error)
	GetDeviceFlowByUserCode(ctx context.Context, userCode string) (*DeviceFlowSession, error)
	CompleteDeviceFlow(ctx context.Context, deviceCode, userID string) error
	CleanupExpiredDeviceFlows(ctx context.Context) error

	// Device tracking.
	RegisterDevice(ctx context.Context, licenseID, fingerprint, name, email string) error
	UpdateDeviceLastSeen(ctx context.Context, licenseID, fingerprint string) error

	// Refresh token management (stored server-side for revocation).
	StoreRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
}
