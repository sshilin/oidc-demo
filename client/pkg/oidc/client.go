package oidc

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

type Config struct {
	ClientId  string
	WellKnown *WellKnownConfiguration
}

func (c *Config) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	conf := &oauth2.Config{
		ClientID: c.ClientId,
		Endpoint: c.WellKnown.Endpoints(),
	}

	tokenSource := conf.TokenSource(ctx, token)
	// Try to refresh access token outside of OAuth2 module.
	// So that it can be retrieved and saved here.
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

func (c *Config) NewClient(ctx context.Context, token *oauth2.Token) (*http.Client, error) {
	return oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)), nil
}
