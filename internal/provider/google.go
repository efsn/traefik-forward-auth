package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Google OIDC provider
type Google struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" default:"select_account" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

// Name of OIDC provider
func (r *Google) Name() string {
	return "google"
}

// Setup Google provider
func (r *Google) Setup() error {
	if r.ClientID == "" || r.ClientSecret == "" {
		return errors.New("providers.google.client-id, providers.google.client-secret must be set")
	}

	r.Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	r.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}
	r.TokenURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/token",
	}
	r.UserURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}

	return nil
}

// GetLoginURL from state
func (r *Google) GetLoginURL(redirectURI, state string) string {
	q := url.Values{}
	q.Set("client_id", r.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", r.Scope)
	if r.Prompt != "" {
		q.Set("prompt", r.Prompt)
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *r.LoginURL
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeCode from code
func (r *Google) ExchangeCode(redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", r.ClientID)
	form.Set("client_secret", r.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	res, err := http.PostForm(r.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)
	return token.Token, err
}

// GetUser from token
func (r *Google) GetUser(token string) (User, error) {
	var user User
	client := &http.Client{}
	req, err := http.NewRequest("GET", r.UserURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)
	return user, err
}
