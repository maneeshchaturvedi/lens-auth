package auth

import "context"

// Store is the database interface the auth library needs.
// Since all services share one DB, this library provides the implementation (postgres.go).
type Store interface {
	// ResolveIdentity resolves the full identity chain for a user.
	// Today: user → license → plan → scopes.
	// Tomorrow: user → org → license → plan → scopes.
	ResolveIdentity(ctx context.Context, userID string) (*Identity, error)

	// GetOrCreateUser finds or creates a user from a WorkOS identity.
	// Returns the internal user ID.
	GetOrCreateUser(ctx context.Context, workosID, email string) (string, error)

	// Device tracking.
	RegisterDevice(ctx context.Context, licenseID, fingerprint, name, email string) error
	UpdateDeviceLastSeen(ctx context.Context, licenseID, fingerprint string) error

	// Refresh token management (stored server-side for revocation).
	StoreRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
}
