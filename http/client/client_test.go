package client

import (
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	stdHttp "net/http"
	"testing"
	"time"
)

func TestStrictHTTPClient(t *testing.T) {
	t.Run("caching transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("strict mode disabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = false

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.NoError(t, err)
			assert.Equal(t, 1, rt.invocations)
		})
	})
	t.Run("TLS transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("sets TLS config", func(t *testing.T) {
			client := NewWithTLSConfig(time.Second, &tls.Config{
				InsecureSkipVerify: true,
			})
			ts := client.client.Transport.(*stdHttp.Transport)
			assert.True(t, ts.TLSClientConfig.InsecureSkipVerify)
		})
	})
	t.Run("error on HTTP call when strictmode is enabled", func(t *testing.T) {
		rt := &stubRoundTripper{}
		DefaultCachingTransport = rt
		StrictMode = true

		client := NewWithCache(time.Second)
		httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
		_, err := client.Do(httpRequest)

		assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
		assert.Equal(t, 0, rt.invocations)
	})
}
