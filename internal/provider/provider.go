package provider

import (
	"context"

	"golang.org/x/oauth2"
)

// Providers support
type Providers struct {
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc"  env-namespace:"OIDC"`
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
}

// Provider interface
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token string) (User, error)
	Setup() error
}

// User profile
type User struct {
	Email string `json:"email"`
}

// OAuthProvider for oauth2 library
type OAuthProvider struct {
	Resource string `long:"resource" env:"RESOURCE" description:"Optional resource indicator"`
	Config   *oauth2.Config
	ctx      context.Context
}

// CopyConfig from uri
func (r *OAuthProvider) CopyConfig(redirectURI string) oauth2.Config {
	config := *r.Config
	config.RedirectURL = redirectURI
	return config
}

// GetOAuthLoginURL from state
func (r *OAuthProvider) GetOAuthLoginURL(redirectURI, state string) string {
	config := r.CopyConfig(redirectURI)
	if r.Resource != "" {
		return config.AuthCodeURL(state, oauth2.SetAuthURLParam("resource", r.Resource))
	}
	return config.AuthCodeURL(state)
}

// GetOAuthExchangeCode token from code
func (r *OAuthProvider) GetOAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := r.CopyConfig(redirectURI)
	return config.Exchange(r.ctx, code)
}

type token struct {
	Token string `json:"accss_token"`
}
