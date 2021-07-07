package v1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
)

func TestHTTPClient_CreateAccessToken(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		server := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK})
		serverURL, _ := url.Parse(server.URL)

		client := HTTPClient{Timeout: time.Second}

		response, err := client.CreateAccessToken(*serverURL, "bearer_token")

		assert.NotNil(t, response)
		assert.NoError(t, err)
	})

	t.Run("error_internal_server_error", func(t *testing.T) {
		server := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError})
		serverURL, _ := url.Parse(server.URL)

		client := HTTPClient{Timeout: time.Second}

		response, err := client.CreateAccessToken(*serverURL, "bearer_token")

		assert.Nil(t, response)
		assert.Error(t, err)
	})

	t.Run("error_invalid_endpoint", func(t *testing.T) {
		client := HTTPClient{Timeout: time.Second}

		response, err := client.CreateAccessToken(url.URL{}, "bearer_token")

		assert.Nil(t, response)
		assert.Error(t, err)
	})
}
