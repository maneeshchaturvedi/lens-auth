package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey struct{ name string }

var identityKey = &contextKey{"identity"}

// IdentityFrom extracts the Identity from the request context.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

func withIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// Middleware returns HTTP middleware that:
// 1. Validates the WorkOS access token (JWT) via JWKS
// 2. Resolves the user's identity (license, tier, scopes) from the DB
// 3. Injects Identity into the request context
func (s *Service) Middleware() func(http.Handler) http.Handler {
	jwksURL := s.workos.JWKSURLFromClient()
	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		s.log.Error("failed to initialize JWKS keyfunc, middleware will reject all requests", "jwks_url", jwksURL, "error", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if jwks == nil {
				(&AuthError{
					StatusCode: http.StatusServiceUnavailable,
					Error:      "service_unavailable",
					Reason:     "authentication service not initialized",
				}).Write(w)
				return
			}

			tokenStr := extractBearer(r)
			if tokenStr == "" {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "missing bearer token",
				}).Write(w)
				return
			}

			// Validate the WorkOS JWT using the request context.
			token, err := jwt.Parse(tokenStr, jwks.KeyfuncCtx(r.Context()))
			if err != nil || !token.Valid {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "invalid token",
				}).Write(w)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "invalid token claims",
				}).Write(w)
				return
			}

			workosUserID, _ := claims["sub"].(string)
			if workosUserID == "" {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "missing subject claim",
				}).Write(w)
				return
			}

			// Resolve email from WorkOS User Management API using sub claim.
			// Access tokens don't include email — it's fetched from the user profile.
			user, err := s.workos.UserManagement().Get(r.Context(), workosUserID)
			if err != nil {
				s.log.Error("failed to fetch WorkOS user", "workos_user_id", workosUserID, "error", err)
				(&AuthError{
					StatusCode: http.StatusInternalServerError,
					Error:      "internal_error",
					Reason:     "failed to resolve user profile",
				}).Write(w)
				return
			}

			email := user.Email

			// Resolve internal identity: user → license → tier → scopes.
			userID, err := s.store.GetOrCreateUser(r.Context(), workosUserID, email)
			if err != nil {
				s.log.Error("failed to resolve user", "workos_user_id", workosUserID, "error", err)
				(&AuthError{
					StatusCode: http.StatusInternalServerError,
					Error:      "internal_error",
					Reason:     "failed to resolve user",
				}).Write(w)
				return
			}

			identity, err := s.store.ResolveIdentity(r.Context(), userID)
			if err != nil {
				s.log.Warn("no active license for user", "user_id", userID, "error", err)
				(&AuthError{
					StatusCode: http.StatusForbidden,
					Error:      "forbidden",
					Reason:     "no active license",
				}).Write(w)
				return
			}

			ctx := withIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns middleware that checks for a specific scope.
func RequireScope(scope Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := IdentityFrom(r.Context())
			if identity == nil {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "no identity in context",
				}).Write(w)
				return
			}

			if !identity.HasScope(scope) {
				requiredPlan := minPlanForScope(scope)
				TierInsufficientError(requiredPlan, "").Write(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func minPlanForScope(scope Scope) Plan {
	for _, plan := range []Plan{PlanFree, PlanPro, PlanTeam} {
		for _, s := range PlanScopes[plan] {
			if s == scope {
				return plan
			}
		}
	}
	return PlanPro
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

