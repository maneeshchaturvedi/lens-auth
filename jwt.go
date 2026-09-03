package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type jwtService struct {
	signingKey  []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type jwtClaims struct {
	jwt.RegisteredClaims
	Email     string  `json:"email"`
	OrgID     string  `json:"org_id,omitempty"`
	LicenseID string  `json:"license_id"`
	Plan      Plan    `json:"plan"`
	Scopes    []Scope `json:"scopes"`
	DeviceID  string  `json:"device_id,omitempty"`
}

func newJWTService(signingKey []byte, accessTTL, refreshTTL time.Duration) *jwtService {
	return &jwtService{
		signingKey: signingKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// issue mints a token pair for a resolved identity.
func (j *jwtService) issue(identity *Identity, deviceID string) (*TokenPair, error) {
	now := time.Now()

	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   identity.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
		},
		Email:     identity.Email,
		OrgID:     identity.OrgID,
		LicenseID: identity.LicenseID,
		Plan:      identity.Plan,
		Scopes:    identity.Scopes,
		DeviceID:  deviceID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(j.signingKey)
	if err != nil {
		return nil, fmt.Errorf("auth: sign access token: %w", err)
	}

	refreshToken, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(j.accessTTL.Seconds()),
	}, nil
}

// validate parses and validates an access token, returning the claims.
func (j *jwtService) validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method: %v", t.Header["alg"])
		}
		return j.signingKey, nil
	})
	if err != nil {
		return nil, ErrTokenInvalid
	}

	jc, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return &Claims{
		UserID:    jc.Subject,
		Email:     jc.Email,
		OrgID:     jc.OrgID,
		LicenseID: jc.LicenseID,
		Plan:      jc.Plan,
		Scopes:    jc.Scopes,
		DeviceID:  jc.DeviceID,
	}, nil
}

// hashRefreshToken returns the SHA256 hex hash of a refresh token.
func hashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateRandomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
