package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"strings"
	"time"

	"github.com/efsn/traefik-forward-auth/internal/provider"
)

// CookieDomain definition
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
}

// CookieDomains CookieDomain slice
type CookieDomains []CookieDomain

// NewCookieDomain generate
func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match whether the given host is match
func (r *CookieDomain) Match(host string) bool {
	if host == r.Domain {
		return true
	}

	if len(host) >= r.SubDomainLen && host[len(host)-r.SubDomainLen:] == r.SubDomain {
		return true
	}

	return false
}

// MarshalFlag get domain
func (r *CookieDomain) MarshalFlag() (string, error) {
	return r.Domain, nil
}

// UnmarshalFlag from given arg
func (r *CookieDomain) UnmarshalFlag(v string) error {
	*r = *NewCookieDomain(v)
	return nil
}

// UnmarshalFlag from given args
func (r *CookieDomains) UnmarshalFlag(v string) error {
	if len(v) > 0 {
		for _, d := range strings.Split(v, ",") {
			cookieDomain := NewCookieDomain(d)
			*r = append(*r, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag get domains
func (r *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *r {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}

// ValidateCookie validate the cookie for request
func ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Unable to decode cookie mac")
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("Unable to generate mac")
	}

	if !hmac.Equal(expected, mac) {
		return "", errors.New("Invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("Unable to parse cookie expiry")
	}

	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("Cookie has expired")
	}
	return parts[2], nil
}

// ValidateEmail check email
func ValidateEmail(email, ruleName string) bool {
	whitelist := config.Whitelist
	domains := config.Domains

	if rule, ok := config.Rules[ruleName]; ok {
		if len(rule.Whitelist) > 0 || len(rule.Domains) > 0 {
			whitelist = rule.Whitelist
			domains = rule.Domains
		}
	}

	if len(whitelist) == 0 && len(domains) == 0 {
		return true
	}

	if len(whitelist) > 0 {
		if ValidateWhitelist(email, whitelist) {
			return true
		}

		if !config.MatchWhitelistOrDomain {
			return false
		}
	}

	if len(domains) > 0 && ValidateDomains(email, domains) {
		return true
	}

	return false
}

// ValidateWhitelist check whitelist
func ValidateWhitelist(email string, whitelist CommaSeparatedList) bool {
	for _, whitelist := range whitelist {
		if email == whitelist {
			return true
		}
	}

	return false
}

// ValidateDomains check domains
func ValidateDomains(email string, domains CommaSeparatedList) bool {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return false
	}

	for _, domain := range domains {
		if domain == parts[1] {
			return true
		}
	}
	return false
}

func redirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forward-Proto"), r.Host)
}

func returnURL(r *http.Request) string {
	return fmt.Sprintf("%s%s", redirectBase(r), r.URL.Path)
}

// redirectURI build redirect uri
func redirectURI(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		p := r.Header.Get("X-Forward-Proto")
		return fmt.Sprintf("%s://%s%s", p, config.AuthHost, config.Path)
	}
	return fmt.Sprintf("%s%s", redirectBase(r), config.Path)
}

func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	reqMatch, reqHost := matchCookieDomains(r.Host)
	authMatch, authHost := matchCookieDomains(config.AuthHost)
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// MakeCookie build cookie
func MakeCookie(r *http.Request, email string) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	v := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    v,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  expires,
	}
}

// ClearCookie check cookie
func ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// MakeCSRFCookie build csrf cookie
func MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     buildCSRFCookieName(nonce),
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie clear csrf cookie from request
func ClearCSRFCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie find csrf cookie
func FindCSRFCookie(r *http.Request, state string) (c *http.Cookie, err error) {
	return r.Cookie(buildCSRFCookieName(state))
}

// ValidateCSRFCookie check csrf  cookie
func ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", errors.New("Invalid CSRF cookie value")
	}

	if c.Value != state[:32] {
		return false, "", "", errors.New("CSRF cookie does not match state")
	}

	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New("Invalid CSRF state format")
	}

	return true, params[:split], params[split+1:], nil
}

// MakeState build request state
func MakeState(r *http.Request, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnURL(r))
}

// ValidateState chech state len
func ValidateState(state string) error {
	if len(state) < 34 {
		return errors.New("Invalid CSRF state value")
	}
	return nil
}

// Nonce generate random nonce
func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}

func cookieDomain(r *http.Request) string {
	_, domain := matchCookieDomains(r.Host)
	return domain
}

func csrfCookieDomain(r *http.Request) string {
	var host string

	if use, domain := useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Host
	}

	p := strings.Split(host, ":")
	return p[0]
}

func matchCookieDomains(domain string) (bool, string) {
	p := strings.Split(domain, ":")
	for _, v := range config.CookieDomains {
		if v.Match(p[0]) {
			return true, v.Domain
		}
	}
	return false, p[0]
}

func cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(hash.Sum(nil)))
}

func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
}

func buildCSRFCookieName(nonce string) string {
	return config.CSRFCookieName + "_" + nonce[:6]
}
