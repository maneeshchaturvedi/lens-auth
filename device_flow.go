package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	deviceFlowTTL      = 15 * time.Minute
	deviceFlowInterval = 5 // seconds
	userCodeLength     = 8 // e.g., "ABCD-1234"
)

type deviceFlowService struct {
	store  Store
	jwt    *jwtService
	workos *workosClient
}

func newDeviceFlowService(store Store, jwt *jwtService, workos *workosClient) *deviceFlowService {
	return &deviceFlowService{store: store, jwt: jwt, workos: workos}
}

// handleCodeRequest handles POST /auth/device/code.
// The CLI calls this to initiate the device flow.
func (d *deviceFlowService) handleCodeRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
		DeviceName  string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	deviceCode, err := generateRandomToken(32)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	userCode, err := generateUserCode()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	session := &DeviceFlowSession{
		DeviceCode:        deviceCode,
		UserCode:          userCode,
		DeviceFingerprint: req.Fingerprint,
		DeviceName:        req.DeviceName,
		Status:            "pending",
		ExpiresAt:         time.Now().Add(deviceFlowTTL),
		CreatedAt:         time.Now(),
	}

	if err := d.store.CreateDeviceFlowSession(r.Context(), session); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	resp := struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURL: r.Header.Get("X-Verification-Base-URL") + "/auth/device/verify",
		ExpiresIn:       int(deviceFlowTTL.Seconds()),
		Interval:        deviceFlowInterval,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleToken handles POST /auth/device/token.
// The CLI polls this until the user completes the browser flow.
func (d *deviceFlowService) handleToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	session, err := d.store.GetDeviceFlowByDeviceCode(r.Context(), req.DeviceCode)
	if err != nil {
		http.Error(w, `{"error":"invalid device code"}`, http.StatusBadRequest)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		(&AuthError{
			StatusCode: http.StatusGone,
			Error:      "expired_token",
			Reason:     "device flow session expired",
		}).Write(w)
		return
	}

	if session.Status == "pending" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "authorization_pending"})
		return
	}

	// Session is complete — resolve identity and issue tokens.
	identity, err := d.store.ResolveIdentity(r.Context(), session.UserID)
	if err != nil {
		http.Error(w, `{"error":"failed to resolve identity"}`, http.StatusInternalServerError)
		return
	}

	tokenPair, err := d.jwt.issue(identity, session.DeviceFingerprint)
	if err != nil {
		http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	// Store the refresh token for revocation support.
	refreshHash := hashRefreshToken(tokenPair.RefreshToken)
	err = d.store.StoreRefreshToken(r.Context(), &RefreshToken{
		TokenHash:         refreshHash,
		UserID:            identity.UserID,
		LicenseID:         identity.LicenseID,
		DeviceFingerprint: session.DeviceFingerprint,
		ExpiresAt:         time.Now().Add(d.jwt.refreshTTL),
		CreatedAt:         time.Now(),
	})
	if err != nil {
		http.Error(w, `{"error":"failed to store refresh token"}`, http.StatusInternalServerError)
		return
	}

	// Register the device.
	_ = d.store.RegisterDevice(r.Context(), identity.LicenseID, session.DeviceFingerprint, session.DeviceName, identity.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

// generateUserCode generates a human-readable code like "ABCD-1234".
func generateUserCode() (string, error) {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O (ambiguous)
	const digits = "0123456789"

	var b strings.Builder
	for i := 0; i < 4; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", fmt.Errorf("auth: generate user code: %w", err)
		}
		b.WriteByte(letters[idx.Int64()])
	}
	b.WriteByte('-')
	for i := 0; i < 4; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("auth: generate user code: %w", err)
		}
		b.WriteByte(digits[idx.Int64()])
	}
	return b.String(), nil
}
