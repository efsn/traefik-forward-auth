package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestGenericOAuthName(t *testing.T) {
	p := GenericOAuth{}
	assert.Equal(t, "generic-oauth", p.Name())
}

func TestGenericOAuthSetup(t *testing.T) {
	assert := assert.New(t)
	p := &GenericOAuth{}

	if err := p.Setup(); assert.Error(err) {
		assert.Equal("providers.generic-oauth.auth-url, providers.generic-oauth.token-url, providers.generic-oauth.user-url, providers.generic-oauth.client-id, providers.generic-oauth.client-secret must be set", err.Error())
	}

	p = &GenericOAuth{
		AuthURL:      "https://elmi.cn/oauth2/auth",
		TokenURL:     "https://elmi.cn/oauth2/token",
		UserURL:      "https://elmi.cn/oauth2/user",
		ClientID:     "idtest",
		ClientSecret: "secrettest",
	}
	err := p.Setup()
	assert.Nil(err)
}

func TestGenericOAuthGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := &GenericOAuth{
		AuthURL:      "https://elmi.cn/oauth2/auth",
		TokenURL:     "https://elmi.cn/oauth2/token",
		UserURL:      "https://elmi.cn/oauth2/user",
		ClientID:     "idtest",
		ClientSecret: "secrettest",
		Scopes:       []string{"scopetest"},
	}

	if err := p.Setup(); err != nil {
		t.Fatal(err)
	}

	uri, err := url.Parse(p.GetLoginURL("https://elmi.cn/_oauth", "state"))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("elmi.cn", uri.Host)
	assert.Equal("/oauth2/auth", uri.Path)

	q := uri.Query()
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"https://elmi.cn/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"state":         []string{"state"},
	}
	assert.Equal(expected, q)
}

func TestGenericOAuthExchangeCode(t *testing.T) {
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

	p := &GenericOAuth{
		AuthURL:      "https://elmi.cn/oauth2/auth",
		TokenURL:     serverURL.String() + "/token",
		UserURL:      "https://elmi.cn/oauth2/user",
		ClientID:     "idtest",
		ClientSecret: "secrettest",
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	token, err := p.ExchangeCode("https://elmi.cn/_oauth", "code")
	assert.Nil(err)
	assert.Equal("oho", token)
}

func TestGenericOAuthGetUser(t *testing.T) {
	assert := assert.New(t)

	server, serverURL := NewOAuthTestServer(t, nil)
	defer server.Close()

	p := &GenericOAuth{
		AuthURL:      "https://elmi.cn/oauth2/auth",
		TokenURL:     "https://elmi.cn/oauth2/token",
		UserURL:      serverURL.String() + "/userinfo",
		ClientID:     "idtest",
		ClientSecret: "secrettest",
	}

	if err := p.Setup(); err != nil {
		t.Fatal(err)
	}

	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	user, err := p.GetUser("oho")
	assert.Nil(err)
	assert.Equal("oho@elmi.cn", user.Email)
}
