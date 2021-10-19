package provider

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDC provider
type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client secret"`
	OAuthProvider
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name for OIDC provider
func (r *OIDC) Name() string {
	return "oidc"
}

// Setup OIDC provider
func (r *OIDC) Setup() error {
	if r.IssuerURL == "" || r.ClientID == "" || r.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}

	var err error
	r.ctx = context.Background()
	r.provider, err = oidc.NewProvider(r.ctx, r.IssuerURL)
	if err != nil {
		return err
	}

	r.Config = &oauth2.Config{
		ClientID:     r.ClientID,
		ClientSecret: r.ClientSecret,
		Endpoint:     r.provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	r.verifier = r.provider.Verifier(&oidc.Config{
		ClientID: r.ClientID,
	})

	return nil
}

// GetLoginURL from OIDC provider
func (r *OIDC) GetLoginURL(redirectURI, state string) string {
	return r.GetOAuthLoginURL(redirectURI, state)
}

// ExchangeCode get token with code
func (r *OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := r.GetOAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

// GetUser by token
func (r *OIDC) GetUser(token string) (User, error) {
	var user User
	idToken, err := r.verifier.Verify(r.ctx, token)
	if err != nil {
		return user, err
	}

	if err := idToken.Claims(&user); err != nil {
		return user, err
	}

	return user, nil
}
