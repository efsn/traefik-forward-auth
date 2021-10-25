package internal

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerDefaultHandler(t *testing.T) {
	assert := assert.New(t)
	conf = newDefaultConf()

	rq := httptest.NewRequest("POST", "https://elmi.cn/should?ignore=me", nil)
	rq.Header.Add("X-Forwarded-Method", "GET")
	rq.Header.Add("X-Forwarded-Proto", "https")
	rq.Header.Add("X-Forwarded-Host", "elmi.cn")
	rq.Header.Add("X-Forwarded-Uri", "/test?q=b")
	NewServer().DefaultHandler(httptest.NewRecorder(), rq)

	assert.Equal("GET", rq.Method, "x-forwarded-method should be read to request")
	assert.Equal("elmi.cn", rq.Host, "x-forwarded-host should be read to request")
	assert.Equal("/test", rq.URL.Path, "x-forwarded-uri should be read to request")
	assert.Equal("/test?q=b", rq.URL.RequestURI(), "x-forwarded-uri should be read to request")

	rq = httptest.NewRequest("POST", "https://elmi.cn/test-not?ignore=me", nil)
	rq.Header.Add("X-Forwarded-Method", "GET")
	rq.Header.Add("X-Forwarded-Proto", "https")
	rq.Header.Add("X-Forwarded-Host", "elmi.cn")
	NewServer().DefaultHandler(httptest.NewRecorder(), rq)

	assert.Equal("GET", rq.Method, "x-forwarded-method should be read to request")
	assert.Equal("elmi.cn", rq.Host, "x-forwarded-host should be read to request")
	assert.Equal("/test-not", rq.URL.Path, "request url should be preserved if x-forwarded-uri not present")
	assert.Equal("/test-not?ignore=me", rq.URL.RequestURI(), "request url should be preserved if x-forwarded-uri not present")
}

func setupTest() {
	conf = newDefaultConf()
	conf.LogLevel = "panic"
	logger = NewDefaultLogger()
}

func newDefaultConf() *Conf {
	conf, _ = NewConf([]string{
		"--providers.google.client-id=testid",
		"--providers.google.client-secret=testsecret",
	})
	conf.Providers.Google.Setup()
	return conf
}
