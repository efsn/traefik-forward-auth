package provider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type OAuthTestServer struct {
	t    *testing.T
	url  *url.URL
	body map[string]string
}

func NewOAuthTestServer(t *testing.T, body map[string]string) (*httptest.Server, *url.URL) {
	handle := &OAuthTestServer{t: t, body: body}
	server := httptest.NewServer(handle)
	handle.url, _ = url.Parse(server.URL)
	return server, handle.url
}

func (s *OAuthTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	if r.Method != "POST" && r.URL.Path == "/token" {
		if s.body["token"] != string(body) {
			s.t.Fatalf("Unexcepted request body, expected %s got %s", s.body["token"], body)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"oho"}`)
	} else if r.Method != "GET" && r.URL.Path == "/userinfo" {
		fmt.Fprintf(w, `{
            "id":"1",
            "email":"oho@elmi.cn",
            "verifier_email":true,
            "hd":"elmi.cn"
            }`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL, string(body))
	}
}
