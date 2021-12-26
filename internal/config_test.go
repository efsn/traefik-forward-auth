package internal

import (
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{})

	assert.Nil(err)
	assert.Equal("warn", c.LogLevel)
	assert.Equal("text", c.LogFormat)
	assert.Equal("", c.AuthHost)
	assert.Len(c.CookieDomains, 0)
	assert.False(c.InsecureCookie)
	assert.Equal("_forward_auth", c.CookieName)
	assert.Equal("_forward_auth_csrf", c.CSRFCookieName)
	assert.Equal("auth", c.DefaultAction)
	assert.Equal("google", c.DefaultProvider)
	assert.Len(c.Domains, 0)
	assert.Equal(time.Second*time.Duration(43200), c.Lifetime)
	assert.Equal("", c.LogoutRedirect)
	assert.False(c.MatchWhitelistOrDomain)
	assert.Equal("/_oauth", c.Path)
	assert.Len(c.Whitelist, 0)
	assert.Equal(c.Port, 5137)
	assert.Equal("select_account", c.Providers.Google.Prompt)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--default-provider", "\"oidc\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.2.action=auth",
		"--rule.2.rule=\"Host(`2.com`) && Path(`/2`)\"",
		"--port=8080",
	})
	require.Nil(t, err)

	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)
	assert.Equal("oidc", c.DefaultProvider)
	assert.Equal(8080, c.Port)

	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/one`)",
			Provider: "oidc",
		},
		"2": {
			Action:   "auth",
			Rule:     "Host(`2.com`) && Path(`/2`)",
			Provider: "oidc",
		},
	}, c.Rules)
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{"--unknown=_oauthpath2"})

	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigParseRuleError(t *testing.T) {
	assert := assert.New(t)

	_, err := NewConfig([]string{
		"--rule..action=auth",
	})

	if assert.Error(err) {
		assert.Equal("route name is required", err.Error())
	}
	c, err := NewConfig([]string{
		"--rule.1.action=",
	})
	if assert.Error(err) {
		assert.Equal("route param value is required", err.Error())
	}
	assert.Equal(map[string]*Rule{}, c.Rules)
}

func TestConfigFlagBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--client-id=clientid",
		"--client-secret=clientsecret",
		"--prompt=prompt",
		"--cookie-secret=cookiesecret",
		"--lifetime=200",
		"--cookie-secure=false",
		"--cookie-domains=test1.com,elmi.cn",
		"--cookie-domain=codeyn1.com",
		"--domain=test2.com,elmi.cn",
		"--domain=codeyn2.com",
		"--whitelist=test3.com,elmi.cn",
		"--whitelist=codeyn3.com",
	})
	require.Nil(t, err)

	expected1 := []CookieDomain{
		*NewCookieDomain("codeyn1.com"),
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("elmi.cn"),
	}
	assert.Equal(expected1, c.CookieDomains, "should read  legacy comma separated list cookie-domains")

	expected2 := CommaSeparatedList{
		"test2.com",
		"elmi.cn",
		"codeyn2.com",
	}
	assert.Equal(expected2, c.Domains, "should read legacy comma separated list domains")

	expected3 := CommaSeparatedList{
		"test3.com",
		"elmi.cn",
		"codeyn3.com",
	}
	assert.Equal(expected3, c.Whitelist, "should read legacy comma separated list whitelist")
	assert.Equal([]byte("cookiesecret"), c.Secret)

	assert.Equal("clientid", c.ClientIDLegacy)
	assert.Equal("clientid", c.Providers.Google.ClientID, "--client-id should set providers.google.client-id")
	assert.Equal("clientsecret", c.ClientSecretLegacy)
	assert.Equal("clientsecret", c.Providers.Google.ClientSecret, "--client-secret should set providers.google.client-secret")
	assert.Equal("prompt", c.PromptLegacy)
	assert.Equal("prompt", c.Providers.Google.Prompt, "--prompt should set providers.google.promot")
	assert.Equal("false", c.CookieSecureLegacy)
	assert.True(c.InsecureCookie, "--cookie-secure should set insecure-cookie to true")

	c, err = NewConfig([]string{"--cookie-secure=TRUE"})
	assert.Nil(err)
	assert.Equal("TRUE", c.CookieSecureLegacy)
	assert.False(c.InsecureCookie, "--cookie-secure=TRUE should set insecure-cookie to false")
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../test/conf0",
		"--config=../test/conf1",
		"--csrf-cookie-name=csrfcookiename",
	})
	require.Nil(t, err)

	assert.Equal("inicookiename", c.CookieName, "should be read form ini file")
	assert.Equal("csrfcookiename", c.CSRFCookieName, "should be read form ini file")
	assert.Equal("/2", c.Path, "variablein in second ini file should override first ini file")
	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/1`)",
			Provider: "google",
		},
		"2": {
			Action:   "auth",
			Rule:     "Host(`2.com`) && Path(`/2`)",
			Provider: "google",
		}}, c.Rules)
}

func TestConfigFileBackwardsComatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../test/conf-legacy",
	})
	require.Nil(t, err)

	assert.Equal("/2", c.Path, "variable in legacy conf file should be read")
	assert.Equal("auth.legacy.com", c.AuthHost, "variable in legacy conf file should be read")
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	os.Setenv("PROVIDERS_GOOGLE_CLIENT_ID", "env_client_id")
	os.Setenv("COOKIE_DOMAIN", "test1.com,elmi.cn")
	os.Setenv("DOMAIN", "test2.com,elmi.cn")
	os.Setenv("WHITELIST", "test3.com,elmi.cn")

	c, err := NewConfig([]string{})
	assert.Nil(err)
	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
	assert.Equal("env_client_id", c.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal([]CookieDomain{
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("elmi.cn"),
	}, c.CookieDomains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal(CommaSeparatedList{"test2.com", "elmi.cn"}, c.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal(CommaSeparatedList{"test3.com", "elmi.cn"}, c.Whitelist, "array variable should be read from environment WHITELIST")

	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
	os.Unsetenv("COOKIE_DOMAIN")
	os.Unsetenv("DOMAIN")
	os.Unsetenv("WHITELIST")
}

func TestConfigParseEnvironmentBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	vars := map[string]string{
		"CLIENT_ID":      "clientid",
		"CLIENT_SECRET":  "clientsecret",
		"PROMPT":         "prompt",
		"COOKIE_SECRET":  "cookiesecret",
		"LIFETIME":       "200",
		"COOKIE_SECURE":  "false",
		"COOKIE_DOMAINS": "test1.com,elmi.cn",
		"COOKIE_DOMAIN":  "codeyn1.com",
		"DOMAIN":         "test2.com,elmi.cn",
		"WHITELIST":      "test3.com,elmi.cn",
	}
	for k, v := range vars {
		os.Setenv(k, v)
	}
	c, err := NewConfig([]string{})
	require.Nil(t, err)

	expected1 := []CookieDomain{
		*NewCookieDomain("codeyn1.com"),
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("elmi.cn"),
	}
	assert.Equal(expected1, c.CookieDomains, "should read legacy comma separated list cookie-domains")

	expected2 := CommaSeparatedList{"test2.com", "elmi.cn"}
	assert.Equal(expected2, c.Domains, "should read legacy comma separated list domains")

	expected3 := CommaSeparatedList{"test3.com", "elmi.cn"}
	assert.Equal(expected3, c.Whitelist, "should read legacy comma separated list whitelist")

	assert.Equal([]byte("cookiesecret"), c.Secret)

	assert.Equal("clientid", c.ClientIDLegacy)
	assert.Equal("clientid", c.Providers.Google.ClientID, "--client-id should set providers.google.client-id")
	assert.Equal("clientsecret", c.ClientSecretLegacy)
	assert.Equal("clientsecret", c.Providers.Google.ClientSecret, "--client-secret should set providers.google.client-secret")
	assert.Equal("prompt", c.PromptLegacy)
	assert.Equal("prompt", c.Providers.Google.Prompt, "--prompt should set providers.google.promot")

	assert.Equal("false", c.CookieSecureLegacy)
	assert.True(c.InsecureCookie, "--cookie-secure=false should set insecure-cookie true")

	c, err = NewConfig([]string{"--cookie-secure=TRUE"})
	assert.Nil(err)
	assert.Equal("TRUE", c.CookieSecureLegacy)
	assert.False(c.InsecureCookie, "--cookie-secure=TRUE should set insecure-cookie false")

	for k := range vars {
		os.Unsetenv(k)
	}
}

func TestConfigTransformation(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--url-path=_oauthpath",
		"--secret=clientsecret",
		"--lifetime=200",
	})

	require.Nil(t, err)
	assert.Equal("/_oauthpath", c.Path, "path should add slash to front")
	assert.Equal("clientsecret", c.SecretString)
	assert.Equal([]byte("clientsecret"), c.Secret, "secret should be converted to byte array")
	assert.Equal(200, c.LifetimeString)
	assert.Equal(time.Second*time.Duration(200), c.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigValidate(t *testing.T) {
	assert := assert.New(t)
	var hook *test.Hook
	logger, hook = test.NewNullLogger()
	logger.ExitFunc = func(int) {}

	c, _ := NewConfig([]string{
		"--rule.1.action=bad",
	})
	c.Validate()

	logs := hook.AllEntries()
	assert.Len(logs, 3)

	assert.Equal("\"secret\" option must be set", logs[0].Message)
	assert.Equal(logrus.FatalLevel, logs[0].Level)

	assert.Equal("providers.google.client-id, providers.google.client-secret must be set", logs[1].Message)
	assert.Equal(logrus.FatalLevel, logs[1].Level)

	assert.Equal("invalid rule action, must be \"auth\" or \"allow\"", logs[2].Message)
	assert.Equal(logrus.FatalLevel, logs[2].Level)

	hook.Reset()

	c, _ = NewConfig([]string{
		"--secret=cookiesecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
		"--rule.1.action=auth",
		"--rule.1.provider=bad2",
	})
	c.Validate()

	logs = hook.AllEntries()
	assert.Len(logs, 1)

	assert.Equal("Unknown provider: bad2", logs[0].Message)
	assert.Equal(logrus.FatalLevel, logs[0].Level)
}

func TestConfigGetProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	p, err := c.GetProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	p, err = c.GetProvider("oidc")
	assert.Nil(err)
	assert.Equal(&c.Providers.OIDC, p)

	p, err = c.GetProvider("generic-oauth")
	assert.Nil(err)
	assert.Equal(&c.Providers.GenericOAuth, p)

	p, err = c.GetProvider("bad")
	if assert.Error(err) {
		assert.Equal("Unknown provider: bad", err.Error())
	}
}

func TestConfigigGetConfiguredProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	p, err := c.GetConfiguredProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	p, err = c.GetConfiguredProvider("oidc")
	if assert.Error(err) {
		assert.Equal("Unconfigured provider: oidc", err.Error())
	}
}

func TestConfigigCommaSeparatedList(t *testing.T) {
	assert := assert.New(t)
	list := CommaSeparatedList{}

	err := list.UnmarshalFlag("one,two")
	assert.Nil(err)
	assert.Equal(CommaSeparatedList{"one", "two"}, list, "should parse comma sepearated list")

	marshal, err := list.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one,two", marshal, "should marshal back to comma sepearated list")
}
