package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// GenericOAuth provider
type GenericOAuth struct {
	AuthURL      string   `long:"auth-url" env:"AUTH_URL" description:"Auth/Login URL"`
	TokenURL     string   `long:"token-url" env:"TOKEN_URL" description:"Token URL"`
	UserURL      string   `long:"user-url" env:"USER_URL" description:"User URL"`
	ClientID     string   `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string   `long:"client-secret" env:"CLIENT_SECRET" description:"Client secret"`
	Scopes       []string `long:"scope" env:"SCOPE" env-delim:"," default:"email" description:"Scopes"`
	TokenStype   string   `long:"token-type" env:"TOKEN_TYPE" default:"header" choice:"header" choice:"query" description:"How token is presented when querying the User URL"`
	OAuthProvider
}

// Name returns the name of the provider
func (r *GenericOAuth) Name() string {
	return "generic-oauth"
}

// Setup performs validation and setup
func (r *GenericOAuth) Setup() error {
	if r.AuthURL == "" || r.TokenURL == "" || r.UserURL == "" || r.ClientID == "" || r.ClientSecret == "" {
		return errors.New("providers.generic-oauth.auth-url, providers.generic-oauth.token-url, providers.generic-oauth.user-url, providers.generic-oauth.client-id, providers.generic-oauth.client-secret must be set")
	}

	r.Config = &oauth2.Config{
		ClientID:     r.ClientID,
		ClientSecret: r.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  r.AuthURL,
			TokenURL: r.TokenURL,
		},
		Scopes: r.Scopes,
	}

	r.ctx = context.Background()
	return nil
}

// GetLoginURL providers the login url for the given redirect uri and state
func (r *GenericOAuth) GetLoginURL(redirectURI, state string) string {
	return r.GetOAuthLoginURL(redirectURI, state)
}

// ExchangeCode exchange the code for the given redirect uri and code for token
func (r *GenericOAuth) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := r.GetOAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// GetUser use the given token and return provider.User object
func (r *GenericOAuth) GetUser(token string) (User, error) {
	var user User

	req, err := http.NewRequest("GET", r.UserURL, nil)
	if err != nil {
		return user, err
	}

	if r.TokenStype == "header" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	} else if r.TokenStype == "query" {
		q := req.URL.Query()
		q.Add("access_token", token)
		req.URL.RawQuery = q.Encode()
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)
	return user, err
}
