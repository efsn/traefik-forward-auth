package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoogleName(t *testing.T) {
	p := Google{}
	assert.Equal(t, "google", p.Name())
}

func TestGoogleSetup(t *testing.T) {
	assert := assert.New(t)
	p := &Google{}

	if err := p.Setup(); assert.Error(err) {
		assert.Equal("providers.google.client-id, providers.google.client-secret must be set", err.Error())
	}

	p = &Google{
		ClientID:     "idtest",
		ClientSecret: "secrettest",
	}

	err := p.Setup()
	assert.Nil(err)
	assert.Equal("https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email", p.Scope)
	assert.Equal("", p.Prompt)
	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}, p.LoginURL)
	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}, p.UserURL)
}

func TestGoogleGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := &Google{
		ClientID:     "idtest",
		ClientSecret: "secrettest",
		Scope:        "scopetest",
		Prompt:       "test select_account",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "google.com",
			Path:   "/auth",
		},
	}

	uri, err := url.Parse(p.GetLoginURL("https://elmi.cn/_oauth", "state"))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("google.com", uri.Host)
	assert.Equal("/auth", uri.Path)

	q := uri.Query()
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"https://elmi.cn/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"prompt":        []string{"test select_account"},
		"state":         []string{"state"},
	}
	assert.Equal(expected, q)
}

func TestGoogleExchangeCode(t *testing.T) {
	assert := assert.New(t)
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"client_secret": []string{"secrettest"},
		"code":          []string{"code"},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{"https://elmi.cn/_oauth"},
	}

	server, serverURL := NewOAuthTestServer(t, map[string]string{
		"token": expected.Encode(),
	})
	defer server.Close()

	p := &Google{
		ClientID:     "idtest",
		ClientSecret: "secrettest",
		Scope:        "scopetest",
		Prompt:       "test select_account",
		TokenURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/token",
		},
	}

	token, err := p.ExchangeCode("https://elmi.cn/_oauth", "code")
	assert.Nil(err)
	assert.Equal("oho", token)
}

func TestGoogleGetUser(t *testing.T) {
	assert := assert.New(t)
	server, serverURL := NewOAuthTestServer(t, nil)
	defer server.Close()

	p := &Google{
		ClientID:     "idtest",
		ClientSecret: "secrettest",
		Scope:        "scopetest",
		Prompt:       "test select_account",
		UserURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/userinfo",
		},
	}

	user, err := p.GetUser("oho")
	assert.Nil(err)
	assert.Equal("oho@elmi.cn", user.Email)
}
