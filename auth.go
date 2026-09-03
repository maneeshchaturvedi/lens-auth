package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 7 * 24 * time.Hour
)

// Config configures the auth service.
type Config struct {
	WorkOSAPIKey    string
	WorkOSClientID  string
	JWTSigningKey   []byte
	AccessTokenTTL  time.Duration // defaults to 15 minutes
	RefreshTokenTTL time.Duration // defaults to 7 days
	UpgradeURL      string        // included in tier_insufficient errors
	OAuthRedirectURI string       // e.g., "https://yourdomain.com/auth/oauth/callback"
}

// Service is the auth facade. Server components interact with this only.
type Service struct {
	jwt        *jwtService
	workos     *workosClient
	device     *deviceFlowService
	store      Store
	config     Config
}

// NewService creates a new auth service.
func NewService(cfg Config, store Store) *Service {
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = defaultAccessTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = defaultRefreshTTL
	}

	jwtSvc := newJWTService(cfg.JWTSigningKey, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	workosSvc := newWorkOSClient(cfg.WorkOSAPIKey, cfg.WorkOSClientID)

	s := &Service{
		jwt:    jwtSvc,
		workos: workosSvc,
		store:  store,
		config: cfg,
	}
	s.device = newDeviceFlowService(store, jwtSvc, workosSvc)
	return s
}

// --- Device flow handlers ---

// HandleDeviceCodeRequest handles POST /auth/device/code.
func (s *Service) HandleDeviceCodeRequest(w http.ResponseWriter, r *http.Request) {
	s.device.handleCodeRequest(w, r)
}

// HandleDeviceToken handles POST /auth/device/token.
func (s *Service) HandleDeviceToken(w http.ResponseWriter, r *http.Request) {
	s.device.handleToken(w, r)
}

// HandleDeviceVerify handles GET /auth/device/verify.
// This renders a page where the user enters their device code,
// then redirects them to WorkOS for authentication.
func (s *Service) HandleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("code")
	if userCode == "" {
		// Render a page with an input field for the user code.
		// In production this would be a proper template.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, deviceVerifyHTML)
		return
	}

	// Validate the user code exists and is pending.
	session, err := s.store.GetDeviceFlowByUserCode(r.Context(), userCode)
	if err != nil || session.Status != "pending" || time.Now().After(session.ExpiresAt) {
		http.Error(w, "Invalid or expired code", http.StatusBadRequest)
		return
	}

	// Redirect to WorkOS for authentication.
	// Pass the device_code in state so the callback can complete the flow.
	authURL, err := s.workos.getAuthorizationURL(s.config.OAuthRedirectURI, session.DeviceCode)
	if err != nil {
		http.Error(w, "Failed to initiate authentication", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleOAuthCallback handles GET /auth/oauth/callback.
// This is called by WorkOS after the user authenticates.
// It works for both dashboard login and device flow completion.
func (s *Service) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange the code for a WorkOS user.
	workosID, email, err := s.workos.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Get or create the internal user.
	userID, err := s.store.GetOrCreateUser(r.Context(), workosID, email)
	if err != nil {
		http.Error(w, "Failed to resolve user", http.StatusInternalServerError)
		return
	}

	// If state contains a device_code, this is a device flow completion.
	if state != "" {
		session, err := s.store.GetDeviceFlowByDeviceCode(r.Context(), state)
		if err == nil && session.Status == "pending" {
			_ = s.store.CompleteDeviceFlow(r.Context(), state, userID)
			// Show success page — the CLI will pick up the token via polling.
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, deviceFlowCompleteHTML)
			return
		}
	}

	// Dashboard login — issue tokens directly.
	identity, err := s.store.ResolveIdentity(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to resolve identity", http.StatusInternalServerError)
		return
	}

	tokenPair, err := s.jwt.issue(identity, "")
	if err != nil {
		http.Error(w, "Failed to issue tokens", http.StatusInternalServerError)
		return
	}

	refreshHash := hashRefreshToken(tokenPair.RefreshToken)
	_ = s.store.StoreRefreshToken(r.Context(), &RefreshToken{
		TokenHash: refreshHash,
		UserID:    identity.UserID,
		LicenseID: identity.LicenseID,
		ExpiresAt: time.Now().Add(s.config.RefreshTokenTTL),
		CreatedAt: time.Now(),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

// HandleRefresh handles POST /auth/refresh.
func (s *Service) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	tokenHash := hashRefreshToken(req.RefreshToken)
	stored, err := s.store.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		(&AuthError{StatusCode: http.StatusUnauthorized, Error: "unauthorized", Reason: "invalid refresh token"}).Write(w)
		return
	}

	if stored.RevokedAt != nil {
		(&AuthError{StatusCode: http.StatusUnauthorized, Error: "unauthorized", Reason: "refresh token revoked"}).Write(w)
		return
	}

	if time.Now().After(stored.ExpiresAt) {
		(&AuthError{StatusCode: http.StatusUnauthorized, Error: "unauthorized", Reason: "refresh token expired"}).Write(w)
		return
	}

	// Re-resolve identity (picks up plan changes, scope changes).
	identity, err := s.store.ResolveIdentity(r.Context(), stored.UserID)
	if err != nil {
		http.Error(w, `{"error":"failed to resolve identity"}`, http.StatusInternalServerError)
		return
	}

	tokenPair, err := s.jwt.issue(identity, stored.DeviceFingerprint)
	if err != nil {
		http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	// Rotate refresh token: revoke old, store new.
	_ = s.revokeAndStoreRefresh(r.Context(), stored, tokenPair, identity)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

func (s *Service) revokeAndStoreRefresh(ctx context.Context, old *RefreshToken, newPair *TokenPair, identity *Identity) error {
	now := time.Now()
	old.RevokedAt = &now

	newHash := hashRefreshToken(newPair.RefreshToken)
	return s.store.StoreRefreshToken(ctx, &RefreshToken{
		TokenHash:         newHash,
		UserID:            identity.UserID,
		LicenseID:         identity.LicenseID,
		DeviceFingerprint: old.DeviceFingerprint,
		ExpiresAt:         time.Now().Add(s.config.RefreshTokenTTL),
		CreatedAt:         time.Now(),
	})
}

// Minimal HTML templates — in production, replace with proper templates.
const deviceVerifyHTML = `<!DOCTYPE html>
<html><body>
<h1>Device Authorization</h1>
<form method="GET">
  <label>Enter the code shown on your device:</label><br>
  <input type="text" name="code" placeholder="ABCD-1234" style="font-size:1.5em;letter-spacing:0.1em" />
  <button type="submit">Continue</button>
</form>
</body></html>`

const deviceFlowCompleteHTML = `<!DOCTYPE html>
<html><body>
<h1>Device Authorized</h1>
<p>You can close this window and return to your terminal.</p>
</body></html>`
