package mfa

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	// Issuer - Miracl Trust OIDC server
	Issuer = "https://api.mpin.io"
)

// Client is a client for that MFA service.
type Client struct {
	OAuthConfig oauth2.Config
	Verifier    *oidc.IDTokenVerifier
	Provider    *oidc.Provider

	clientID     string
	clientSecret string
	redirectURL  string
	issuer       string
}

// New returns new MFA client.
func New(ctx context.Context, clientID, clientSecret, redirectURL string, opts ...func(*Client)) (*Client, error) {
	c := &Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		issuer:       Issuer,
	}
	for _, f := range opts {
		f(c)
	}

	return c.init(ctx)
}

func (c *Client) init(ctx context.Context) (*Client, error) {
	var err error

	c.Provider, err = oidc.NewProvider(ctx, c.issuer)
	if err != nil {
		return nil, err
	}

	c.Verifier = c.Provider.Verifier(&oidc.Config{
		ClientID: c.clientID,
	})

	c.OAuthConfig = oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     c.Provider.Endpoint(),
		RedirectURL:  c.redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	return c, nil
}

// Verify verifis the IDToken.
func (c *Client) Verify(ctx context.Context, code string) (*oauth2.Token, error) {
	oauth2Token, err := c.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	_, err = c.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID Token verification failed: %v", err)
	}

	return oauth2Token, nil
}

// WithDiscoveryURL sets DiscoveryURL.
func WithDiscoveryURL(url string) func(*Client) {
	return func(c *Client) {
		c.issuer = url
	}
}
