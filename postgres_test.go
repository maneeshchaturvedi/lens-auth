package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration test: needs a scratch database with the llmlens schema
// (users, licenses). Skipped unless LENS_TEST_DATABASE_URL is set. Never
// point it at production: it creates and deletes users and licenses.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("LENS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("LENS_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// userWithLicense creates a user holding one license in the given state.
func userWithLicense(t *testing.T, pool *pgxpool.Pool, status string, expiresAt *time.Time) string {
	t.Helper()
	ctx := context.Background()
	var userID, email string
	if err := pool.QueryRow(ctx, `
		INSERT INTO llmlens.users (id, workos_id, email)
		VALUES (gen_random_uuid(), 'test-' || gen_random_uuid(), gen_random_uuid() || '@example.test')
		RETURNING id, email`).Scan(&userID, &email); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO llmlens.licenses (id, license_key, email, plan, status, expires_at)
		VALUES (gen_random_uuid(), 'test-' || gen_random_uuid(), $1, 'pro', $2, $3)`,
		email, status, expiresAt); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		pool.Exec(ctx, `DELETE FROM llmlens.licenses WHERE email = $1`, email)
		pool.Exec(ctx, `DELETE FROM llmlens.users WHERE id = $1`, userID)
	})
	return userID
}

// A license grants access while active (within any term) or cancelled
// within the period already paid for — never after it ends.
func TestResolveIdentityLicenseStates(t *testing.T) {
	pool := testPool(t)
	store := NewPostgresStore(pool)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	cases := []struct {
		name      string
		status    string
		expiresAt *time.Time
		resolves  bool
	}{
		{"active without term", "active", nil, true},
		{"active within term", "active", &future, true},
		{"active past term", "active", &past, false},
		{"cancelled within paid period", "cancelled", &future, true},
		{"cancelled after paid period", "cancelled", &past, false},
		{"cancelled without paid period", "cancelled", nil, false},
		{"expired", "expired", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := userWithLicense(t, pool, c.status, c.expiresAt)
			id, err := store.ResolveIdentity(context.Background(), user)
			if c.resolves {
				if err != nil {
					t.Fatalf("want identity, got %v", err)
				}
				if id.Plan != "pro" {
					t.Fatalf("plan %q, want pro", id.Plan)
				}
				return
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("want no usable license, got %v (identity %+v)", err, id)
			}
		})
	}
}
