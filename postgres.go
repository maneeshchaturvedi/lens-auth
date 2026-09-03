package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against the shared llmlens Supabase database.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a Store backed by a pgxpool connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (p *PostgresStore) ResolveIdentity(ctx context.Context, userID string) (*Identity, error) {
	var id Identity
	var plan string
	err := p.pool.QueryRow(ctx, `
		SELECT u.id, u.email, l.id, l.plan, COALESCE(l.org_name, '')
		FROM llmlens.users u
		JOIN llmlens.licenses l ON l.email = u.email
		WHERE u.id = $1 AND l.status = 'active'
		ORDER BY l.created_at DESC
		LIMIT 1
	`, userID).Scan(&id.UserID, &id.Email, &id.LicenseID, &plan, &id.OrgID)
	if err != nil {
		return nil, fmt.Errorf("auth: resolve identity: %w", err)
	}

	id.Plan = Plan(plan)
	id.Scopes = ScopesForPlan(id.Plan)
	return &id, nil
}

func (p *PostgresStore) GetOrCreateUser(ctx context.Context, workosID, email string) (string, error) {
	var userID string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO llmlens.users (workos_id, email)
		VALUES ($1, $2)
		ON CONFLICT (workos_id) DO UPDATE SET email = EXCLUDED.email
		RETURNING id
	`, workosID, email).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("auth: get or create user: %w", err)
	}
	return userID, nil
}

func (p *PostgresStore) RegisterDevice(ctx context.Context, licenseID, fingerprint, name, email string) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO llmlens.license_devices (license_id, device_fingerprint, device_name, user_email, activated_at, last_seen_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (license_id, device_fingerprint)
		DO UPDATE SET device_name = EXCLUDED.device_name, last_seen_at = NOW()
	`, licenseID, fingerprint, name, email)
	if err != nil {
		return fmt.Errorf("auth: register device: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateDeviceLastSeen(ctx context.Context, licenseID, fingerprint string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE llmlens.license_devices SET last_seen_at = NOW()
		WHERE license_id = $1 AND device_fingerprint = $2
	`, licenseID, fingerprint)
	if err != nil {
		return fmt.Errorf("auth: update device last seen: %w", err)
	}
	return nil
}

func (p *PostgresStore) StoreRefreshToken(ctx context.Context, token *RefreshToken) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO llmlens.refresh_tokens (token_hash, user_id, license_id, device_fingerprint, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.TokenHash, token.UserID, token.LicenseID, token.DeviceFingerprint,
		token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("auth: store refresh token: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	t := &RefreshToken{}
	err := p.pool.QueryRow(ctx, `
		SELECT id, token_hash, user_id, license_id, device_fingerprint, expires_at, revoked_at, created_at
		FROM llmlens.refresh_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.TokenHash, &t.UserID, &t.LicenseID,
		&t.DeviceFingerprint, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("auth: refresh token not found: %w", err)
		}
		return nil, fmt.Errorf("auth: get refresh token: %w", err)
	}
	return t, nil
}

func (p *PostgresStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE llmlens.refresh_tokens SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL
	`, tokenHash)
	if err != nil {
		return fmt.Errorf("auth: revoke refresh token: %w", err)
	}
	return nil
}

func (p *PostgresStore) RevokeRefreshTokensForUser(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE llmlens.refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("auth: revoke refresh tokens: %w", err)
	}
	return nil
}
