package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthValidateCookie(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	rq, _ := http.NewRequest("GeT", "https://elmi.cn", nil)
	ck := &http.Cookie{}

	ck.Value = ""
	_, err := ValidateCookie(rq, ck)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}

	ck.Value = "1|2"
	_, err = ValidateCookie(rq, ck)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}

	ck.Value = "a|b|c|d"
	_, err = ValidateCookie(rq, ck)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}

	ck.Value = "MQ==|a|c"
	_, err = ValidateCookie(rq, ck)
	if assert.Error(err) {
		assert.Equal("Invalid cookie mac", err.Error())
	}

	conf.Lifetime = time.Second * time.Duration(-1)
	ck = MakeCookie(rq, "oho@elmi.cn")
	_, err = ValidateCookie(rq, ck)
	if assert.Error(err) {
		assert.Equal("Cookie has expired", err.Error())
	}

	conf.Lifetime = time.Second * time.Duration(10)
	ck = MakeCookie(rq, "oho@elmi.cn")
	email, err := ValidateCookie(rq, ck)
	assert.Nil(err, "valid request  should  not return an error")
	assert.Equal("oho@elmi.cn", email, "valid request should return user email")
}

func TestAuthValidateEmail(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})

	b := ValidateEmail("test@elmi.cn", "test")
	assert.True(b, "should allow any domain if email domain is not defined")

	conf.Domains = []string{"elmi.cn"}
	b = ValidateEmail("elmi@test.cn", "test")
	assert.False(b, "should not allow user from another domain")

	b = ValidateEmail("test@elmi.cn", "test")
	assert.True(b, "should allow user from allowed domain")

	conf.Domains = []string{}
	conf.Whitelist = []string{"test@elmi.cn"}
	b = ValidateEmail("test@elmi1.cn", "test")
	assert.False(b, "should not allow user not in whitelist")
	b = ValidateEmail("test@elmi.cn", "test")
	assert.True(b, "should allow user in whitelist")

	conf.Domains = []string{"test.cn"}
	conf.Whitelist = []string{"test@elmi.cn"}
	conf.MatchWhitelistOrDomain = false
	b = ValidateEmail("test@elmi1.cn", "test")
	assert.False(b, "should not allow user not in")
	b = ValidateEmail("test@test.cn", "test")
	assert.False(b, "should not allow user from allowed doman")
	b = ValidateEmail("test@elmi.cn", "test")
	assert.True(b, "should allow user in whitelist")

	conf.Domains = []string{"test.cn"}
	conf.Whitelist = []string{"test@elmi.cn"}
	conf.MatchWhitelistOrDomain = true
	b = ValidateEmail("test@elmi1.cn", "test")
	assert.False(b, "should not allow user not in")
	b = ValidateEmail("test@test.cn", "test")
	assert.True(b, "should allow user from allowed doman")
	b = ValidateEmail("test@elmi.cn", "test")
	assert.True(b, "should allow user in whitelist")
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	ck := &http.Cookie{}
	state := ""

	ck.Value = ""
	valid, _, _, err := ValidateCSRFCookie(ck, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}

	state = "12345678901234567890123456789012:oho"
	ck.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(ck, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state format", err.Error())
	}

	state = "12345678901234567890123456789012:oho:123"
	ck.Value = "12345678901234567890123456789012"
	valid, p, r, err := ValidateCSRFCookie(ck, state)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("oho", p, "valid request should return provider")
	assert.Equal("123", r, "valid request should return redirect")
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)
	n1, err := Nonce()
	assert.Nil(err, "error generate nonce")
	assert.Len(n1, 32, "length should be 32")

	n2, err := Nonce()
	assert.Nil(err, "error generate  nonce")
	assert.Len(n2, 32, "length should be 32")

	assert.NotEqual(n1, n2, "nonce should be different")
}

func TestRedirectURI(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	rq := httptest.NewRequest("GET", "https://app.elmi.cn/hi", nil)
	rq.Header.Add("X-Forward-Proto", "https")

	uri, err := url.Parse(redirectURI(rq))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("app.elmi.cn", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	conf.AuthHost = "auth.elmi.cn"
	uri, err = url.Parse(redirectURI(rq))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("app.elmi.cn", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	conf.AuthHost = "auth.elmi.cn"
	conf.CookieDomains = []CookieDomain{*NewCookieDomain("elmi.cn")}

	uri, err = url.Parse(redirectURI(rq))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("auth.elmi.cn", uri.Host)
	assert.Equal("/_oauth", uri.Path)
}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	rq, _ := http.NewRequest("GET", "http://app.elmi.cn", nil)
	rq.Header.Add("X-Forward-Host", "app.elmi.cn")

	ck := MakeCookie(rq, "test@elmi.cn")
	assert.Equal("_forward_auth", ck.Name)
	parts := strings.Split(ck.Value, "|")
	assert.Len(parts, 3, "cookie should be 3 parts")
	_, err := ValidateCookie(rq, ck)
	assert.Nil(err)
	assert.Equal("/", ck.Path)
	assert.Equal("app.elmi.cn", ck.Domain)
	assert.True(ck.Secure)

	expires := time.Now().Local().Add(conf.Lifetime)
	assert.WithinDuration(expires, ck.Expires, time.Second*10)

	conf.CookieName = "test"
	conf.InsecureCookie = true
	ck = MakeCookie(rq, "test@elmi.cn")
	assert.Equal("test", ck.Name)
	assert.False(ck.Secure)
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	rq, _ := http.NewRequest("GET", "https://test.elmi.cn", nil)
	rq.Header.Add("X-Forward-Host", "test.elmi.cn")

	ck := MakeCSRFCookie(rq, "123456789012345678901234567890")
	assert.Equal("_forward_auth_csrf_123456", ck.Name)
	assert.Equal("test.elmi.cn", ck.Domain)

	conf.CookieDomains = []CookieDomain{*NewCookieDomain("elmi.cn")}
	ck = MakeCSRFCookie(rq, "321123456789012345678901234567890")
	assert.Equal("_forward_auth_csrf_321123", ck.Name)
	assert.Equal("test.elmi.cn", ck.Domain)

	conf.AuthHost = "auth.elmi.cn"
	conf.CookieDomains = []CookieDomain{*NewCookieDomain("elmi.cn")}
	ck = MakeCSRFCookie(rq, "2123456789012345678901234567890")
	assert.Equal("_forward_auth_csrf_212345", ck.Name)
	assert.Equal("elmi.cn", ck.Domain)
}

func TestAuthMakeState(t *testing.T) {
	assert := assert.New(t)
	state := "123:"
	if err := ValidateState(state); assert.Error(err) {
		assert.Equal("Invalid CSRF state value", err.Error())
	}

	state = "1234567890:p1234567890:url1234567890"
	err := ValidateState(state)
	assert.Nil(err, "valid request should not return an effor")
}

func TestAuthClearCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	conf, _ = NewConf([]string{})
	rq, _ := http.NewRequest("GET", "https://elmi.cn", nil)
	ck := ClearCSRFCookie(rq, &http.Cookie{Name: "testCSRFCookie"})
	assert.Equal("testCSRFCookie", ck.Name)
	if ck.Value != "" {
		t.Error("should create cookie with empty")
	}
}

func TestAuthCookieDomainMatch(t *testing.T) {
	assert := assert.New(t)
	cd := NewCookieDomain("elmi.cn")
	assert.True(cd.Match("elmi.cn"), "exact domain should match")
	assert.True(cd.Match("test.elmi.cn"), "subdomain should match")
	assert.True(cd.Match("x.x.x.x.test.elmi.cn"), "subdomain should match")
	assert.False(cd.Match("testelmi.cn"), "derived domain should not match")
	assert.False(cd.Match("test.cn"), "other domain sohuld not match")
}

func TestAuthCookieDomains(t *testing.T) {
	assert := assert.New(t)
	cds := CookieDomains{}

	err := cds.UnmarshalFlag("elmi.cn,elmi.test")
	assert.Nil(err)

	excepted := CookieDomains{
		CookieDomain{
			Domain:       "elmi.cn",
			DomainLen:    7,
			SubDomain:    ".elmi.cn",
			SubDomainLen: 8,
		},
		CookieDomain{
			Domain:       "elmi.test",
			DomainLen:    9,
			SubDomain:    ".elmi.test",
			SubDomainLen: 10,
		},
	}
	assert.Equal(excepted, cds)

	marshal, err := cds.MarshalFlag()
	assert.Nil(err)
	assert.Equal("elmi.cn,elmi.test", marshal)
}
