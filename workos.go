package auth

import (
	"context"
	"fmt"

	"github.com/workos/workos-go/v4/pkg/usermanagement"
)

type workosClient struct {
	um       *usermanagement.Client
	clientID string
}

func newWorkOSClient(apiKey, clientID string) *workosClient {
	um := usermanagement.NewClient(apiKey)
	return &workosClient{
		um:       um,
		clientID: clientID,
	}
}

// getAuthorizationURL returns the WorkOS OAuth URL for browser-based login.
// redirectURI is the callback URL on your server (e.g., /auth/oauth/callback).
// state is an opaque value for CSRF protection.
func (w *workosClient) getAuthorizationURL(redirectURI, state string) (string, error) {
	url, err := w.um.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
		Provider:    "authkit",
		ClientID:    w.clientID,
		RedirectURI: redirectURI,
		State:       state,
	})
	if err != nil {
		return "", fmt.Errorf("auth: workos authorization url: %w", err)
	}
	return url.String(), nil
}

// exchangeCode exchanges an authorization code for a WorkOS user.
// Returns the WorkOS user ID and email.
func (w *workosClient) exchangeCode(ctx context.Context, code string) (workosID, email string, err error) {
	resp, err := w.um.AuthenticateWithCode(ctx, usermanagement.AuthenticateWithCodeOpts{
		ClientID: w.clientID,
		Code:     code,
	})
	if err != nil {
		return "", "", fmt.Errorf("auth: workos code exchange: %w", err)
	}
	return resp.User.ID, resp.User.Email, nil
}
