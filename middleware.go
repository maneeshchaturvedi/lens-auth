package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey struct{ name string }

var identityKey = &contextKey{"identity"}

// IdentityFrom extracts the Identity from the request context.
// Returns nil if no identity is present (i.e., middleware was not applied).
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

func withIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// Middleware returns HTTP middleware that validates the bearer token
// and injects the Identity into the request context.
func (s *Service) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     "missing bearer token",
				}).Write(w)
				return
			}

			claims, err := s.jwt.validate(token)
			if err != nil {
				(&AuthError{
					StatusCode: http.StatusUnauthorized,
					Error:      "unauthorized",
					Reason:     err.Error(),
				}).Write(w)
				return
			}

			identity := &Identity{
				UserID:    claims.UserID,
				Email:     claims.Email,
				OrgID:     claims.OrgID,
				LicenseID: claims.LicenseID,
				Plan:      claims.Plan,
				Scopes:    claims.Scopes,
			}

			ctx := withIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns middleware that checks for a specific scope.
// Must be chained after Service.Middleware().
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

// minPlanForScope returns the cheapest plan that grants a given scope.
func minPlanForScope(scope Scope) Plan {
	for _, plan := range []Plan{PlanFree, PlanPro, PlanTeam} {
		for _, s := range PlanScopes[plan] {
			if s == scope {
				return plan
			}
		}
	}
	return PlanPro // fallback
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
