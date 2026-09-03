package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashToken returns the SHA256 hex hash of a token (for storage without storing the raw value).
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
