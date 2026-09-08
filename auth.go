package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/workos/workos-go/v10"
)

const defaultRefreshTTL = 7 * 24 * time.Hour

// Config configures the auth service.
type Config struct {
	WorkOSAPIKey     string
	WorkOSClientID   string
	OAuthRedirectURI string // e.g., "https://app.llmlens.com/auth/oauth/callback"
	UpgradeURL       string // included in tier_insufficient errors
	Logger           *slog.Logger
}

// Service is the auth facade. Server components interact with this only.
type Service struct {
	workos *workos.Client
	store  Store
	config Config
	log    *slog.Logger
}

// NewService creates a new auth service.
func NewService(cfg Config, store Store) *Service {
	client := workos.NewClient(cfg.WorkOSAPIKey, workos.WithClientID(cfg.WorkOSClientID))
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		workos: client,
		store:  store,
		config: cfg,
		log:    logger,
	}
}

// resolveAndStoreRefresh is the shared post-authentication logic:
// maps a WorkOS user to an internal identity and stores the refresh token hash.
func (s *Service) resolveAndStoreRefresh(r *http.Request, authResp *workos.AuthenticateResponse) (*Identity, error) {
	if authResp.User == nil {
		return nil, errors.New("auth: workos response missing user")
	}

	userID, err := s.store.GetOrCreateUser(r.Context(), authResp.User.ID, authResp.User.Email)
	if err != nil {
		return nil, err
	}

	identity, err := s.store.ResolveIdentity(r.Context(), userID)
	if err != nil {
		return nil, err
	}

	refreshHash := hashToken(authResp.RefreshToken)
	if err := s.store.StoreRefreshToken(r.Context(), &RefreshToken{
		TokenHash: refreshHash,
		UserID:    identity.UserID,
		LicenseID: identity.LicenseID,
		ExpiresAt: time.Now().Add(defaultRefreshTTL),
		CreatedAt: time.Now(),
	}); err != nil {
		s.log.Error("failed to store refresh token", "user_id", identity.UserID, "error", err)
	}

	return identity, nil
}

// HandleDeviceCodeRequest handles POST /auth/device/code.
// The CLI calls this to start the device authorization flow.
func (s *Service) HandleDeviceCodeRequest(w http.ResponseWriter, r *http.Request) {
	resp, err := s.workos.AuthKitStartDeviceAuthorization(r.Context())
	if err != nil {
		s.log.Error("failed to start device authorization", "error", err)
		http.Error(w, `{"error":"failed to start device authorization"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleDeviceToken handles POST /auth/device/token.
// The CLI polls this until the user completes the browser flow.
func (s *Service) HandleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceCode string  `json:"device_code"`
		Interval   float64 `json:"interval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	interval := 5
	if req.Interval > 0 {
		interval = int(req.Interval)
	}

	authResp, err := s.workos.AuthKitPollDeviceCode(r.Context(), req.DeviceCode, interval)
	if err != nil {
		// WorkOS returns a 400 APIError with code "authorization_pending"
		// while the user hasn't approved yet — relay as 202 to the CLI.
		var apiErr *workos.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode == "authorization_pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "authorization_pending"})
			return
		}
		s.log.Error("device code poll failed", "error", err)
		http.Error(w, `{"error":"device authorization failed"}`, http.StatusInternalServerError)
		return
	}

	identity, err := s.resolveAndStoreRefresh(r, authResp)
	if err != nil {
		s.log.Error("failed to resolve identity after device auth", "error", err)
		http.Error(w, `{"error":"failed to resolve identity"}`, http.StatusInternalServerError)
		return
	}
	_ = identity // identity resolved successfully; tokens are from WorkOS

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	})
}

// HandleOAuthCallback handles GET /auth/oauth/callback.
// Called by WorkOS after browser-based authentication (dashboard login).
func (s *Service) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	authResp, err := s.workos.UserManagement().AuthenticateWithCode(r.Context(), &workos.UserManagementAuthenticateWithCodeParams{
		Code: code,
	})
	if err != nil {
		s.log.Error("workos code exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	identity, err := s.resolveAndStoreRefresh(r, authResp)
	if err != nil {
		s.log.Error("failed to resolve identity after oauth", "error", err)
		http.Error(w, "Failed to resolve identity", http.StatusInternalServerError)
		return
	}
	_ = identity

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	})
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

	// Check if refresh token has been revoked locally.
	tokenHash := hashToken(req.RefreshToken)
	stored, err := s.store.GetRefreshToken(r.Context(), tokenHash)
	if err == nil && stored.RevokedAt != nil {
		(&AuthError{StatusCode: http.StatusUnauthorized, Error: "unauthorized", Reason: "refresh token revoked"}).Write(w)
		return
	}

	// Exchange with WorkOS for new tokens.
	authResp, err := s.workos.UserManagement().AuthenticateWithRefreshToken(r.Context(), &workos.UserManagementAuthenticateWithRefreshTokenParams{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		s.log.Error("workos refresh token exchange failed", "error", err)
		(&AuthError{StatusCode: http.StatusUnauthorized, Error: "unauthorized", Reason: "invalid refresh token"}).Write(w)
		return
	}

	// Revoke old token in our DB.
	if stored != nil {
		if err := s.store.RevokeRefreshToken(r.Context(), stored.TokenHash); err != nil {
			s.log.Error("failed to revoke old refresh token", "error", err)
		}
	}

	// Store new refresh token and re-resolve identity (picks up plan changes).
	identity, err := s.resolveAndStoreRefresh(r, authResp)
	if err != nil {
		s.log.Error("failed to resolve identity after refresh", "error", err)
		http.Error(w, `{"error":"failed to resolve identity"}`, http.StatusInternalServerError)
		return
	}
	_ = identity

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	})
}

// GetAuthorizationURL returns the WorkOS OAuth URL for browser-based login.
func (s *Service) GetAuthorizationURL(state string) (string, error) {
	return s.workos.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: s.config.OAuthRedirectURI,
		State:       &state,
	})
}
