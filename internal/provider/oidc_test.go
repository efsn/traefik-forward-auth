package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

type OIDCTestServer struct {
	t    *testing.T
	url  *url.URL
	key  *rsaKey
	body map[string]string
}

type rsaKey struct {
	key    *rsa.PrivateKey
	alg    jose.SignatureAlgorithm
	jwkPub *jose.JSONWebKey
	jwkPrv *jose.JSONWebKey
}

// implements Handler
func NewOIDCTestServer(t *testing.T, key *rsaKey, body map[string]string) (*httptest.Server, *url.URL) {
	handler := &OIDCTestServer{t: t, key: key, body: body}
	server := httptest.NewServer(handler)
	handler.url, _ = url.Parse(server.URL)
	return server, handler.url
}

func (s *OIDCTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if r.URL.Path == "/.well-known/openid-configuration" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
            "issuer": "`+s.url.String()+`",
            "authorization_endpoint":"`+s.url.String()+`/auth",
            "token_endpoint":"`+s.url.String()+`/token",
            "jwks_uri":"`+s.url.String()+`/jwks"
        }`)
	} else if r.URL.Path == "/token" {
		if b, ok := s.body["token"]; ok {
			if b != string(body) {
				s.t.Fatal("Unexcepted request body, expected", b, "got", string(body))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
            "access_token":"123",
            "id_token":"id123"
        }`)
	} else if r.URL.Path == "/jwks" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[`+s.key.pubJWK(s.t)+`]}`)
	} else {
		s.t.Fatal("Unexcepted request: ", r.URL, string(body))
	}
}

func TestOIDCName(t *testing.T) {
	p := OIDC{}
	assert.Equal(t, "oidc", p.Name())
}

func TestOIDCSetup(t *testing.T) {
	assert := assert.New(t)
	p := OIDC{}
	err := p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set", err.Error())
	}
}

func TestOIDCGetLoginURL(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, _ := setupOIDCTest(t, nil)
	defer server.Close()

	uri, err := url.Parse(provider.GetLoginURL("http://elmi.cn/_oauth", "state"))
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	q := uri.Query()
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://elmi.cn/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
	}
	assert.Equal(expected, q)
	provider.Resource = "resourcetest"

	uri, err = url.Parse(provider.GetLoginURL("http://elmi.cn/_oauth", "state"))
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	q = uri.Query()
	expected = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://elmi.cn/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
		"resource":      []string{"resourcetest"},
	}
	assert.Equal(expected, q)
	assert.Equal("", provider.Config.RedirectURL)
}

func TestOIDCExchangeCode(t *testing.T) {
	assert := assert.New(t)
	provider, server, _, _ := setupOIDCTest(t, map[string]map[string]string{
		"token": {
			"code":         "code",
			"grant_type":   "authorization_code",
			"redirect_uri": "http://elmi.cn/_oauth",
		},
	})

	defer server.Close()

	token, err := provider.ExchangeCode("http://elmi.cn/_oauth", "code")
	assert.Nil(err)
	assert.Equal("id123", token)
}

func TestOIDCGetUser(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, key := setupOIDCTest(t, nil)
	defer server.Close()

	// Generic JWT
	token := key.sign(t, []byte(`{
        "iss":"`+serverURL.String()+`",
        "exp":`+strconv.FormatInt(time.Now().Add(2*time.Minute).Unix(), 10)+`,
        "aud":"idtest",
        "sub":"1",
        "email":"oho@elmi.cn",
        "email_verified":true
    }`))

	user, err := provider.GetUser(token)
	assert.Nil(err)
	assert.Equal("oho@elmi.cn", user.Email)
}

func newRSAKey() (*rsaKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		return nil, err
	}

	return &rsaKey{
		key: key,
		alg: jose.RS256,
		jwkPub: &jose.JSONWebKey{
			Key:       key.Public(),
			Algorithm: string(jose.RS256),
		},
		jwkPrv: &jose.JSONWebKey{
			Key:       key,
			Algorithm: string(jose.RS256),
		},
	}, nil
}

func (r *rsaKey) pubJWK(t *testing.T) string {
	b, err := r.jwkPub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// create a jws with the private key from the provide  payload
func (r *rsaKey) sign(t *testing.T, payload []byte) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: r.alg,
		Key:       r.key,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func setupOIDCTest(t *testing.T, bodies map[string]map[string]string) (*OIDC, *httptest.Server, *url.URL, *rsaKey) {
	k, err := newRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	body := make(map[string]string)
	if bodies != nil {
		for m, vs := range bodies {
			q := url.Values{}
			for k, v := range vs {
				q.Set(k, v)
			}
			body[m] = q.Encode()
		}
	}

	server, url := NewOIDCTestServer(t, k, body)

	p := &OIDC{
		ClientID:     "idtest",
		ClientSecret: "secrettest",
		IssuerURL:    url.String(),
	}
	if err = p.Setup(); err != nil {
		t.Fatal(err)
	}
	return p, server, url, k
}
