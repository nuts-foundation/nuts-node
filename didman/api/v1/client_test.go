package v1

import (
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClient_UpdateContactInformation(t *testing.T) {
	info := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: info})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.UpdateContactInformation("abc", info)
		assert.NoError(t, err)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.UpdateContactInformation("def", info)
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		err := c.UpdateContactInformation("def", info)
		assert.Error(t, err)
	})
}

func TestHTTPClient_GetContactInformation(t *testing.T) {
	expected := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: expected})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := c.GetContactInformation("abc")
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("no contact info", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: nil})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := c.GetContactInformation("abc")
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: nil})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := c.GetContactInformation("abc")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHTTPClient_AddEndpoint(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNoContent})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.AddEndpoint("abc", "type", "some-url")
		assert.NoError(t, err)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.AddEndpoint("abc", "type", "some-url")
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		err := c.AddEndpoint("abc", "type", "some-url")
		assert.Error(t, err)
	})
}

func TestHTTPClient_AddCompoundService(t *testing.T) {
	refs := map[string]string{
		"foo": "bar",
	}
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNoContent})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.AddCompoundService("abc", "type", refs)
		assert.NoError(t, err)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.AddCompoundService("abc", "type", refs)
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		err := c.AddCompoundService("abc", "type", refs)
		assert.Error(t, err)
	})
}
