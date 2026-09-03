package auth

import (
	"encoding/json"
	"errors"
	"net/http"
)

var (
	ErrTokenExpired      = errors.New("auth: token expired")
	ErrTokenInvalid      = errors.New("auth: token invalid")
	ErrTokenMissing      = errors.New("auth: token missing")
	ErrRefreshRevoked    = errors.New("auth: refresh token revoked")
	ErrLicenseInactive   = errors.New("auth: license not active")
	ErrDeviceFlowPending = errors.New("auth: device flow authorization pending")
	ErrDeviceFlowExpired = errors.New("auth: device flow session expired")
)

// AuthError is a structured error returned to clients.
type AuthError struct {
	StatusCode   int    `json:"-"`
	Error        string `json:"error"`
	Reason       string `json:"reason,omitempty"`
	RequiredPlan Plan   `json:"required_plan,omitempty"`
	UpgradeURL   string `json:"upgrade_url,omitempty"`
}

func TierInsufficientError(required Plan, upgradeURL string) *AuthError {
	return &AuthError{
		StatusCode:   http.StatusForbidden,
		Error:        "forbidden",
		Reason:       "tier_insufficient",
		RequiredPlan: required,
		UpgradeURL:   upgradeURL,
	}
}

func (e *AuthError) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(e)
}
