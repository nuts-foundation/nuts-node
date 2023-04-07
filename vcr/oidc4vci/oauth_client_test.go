package oidc4vci

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func Test_httpOAuth2Client_RequestAccessToken(t *testing.T) {
	httpClient := &http.Client{}
	params := map[string]string{"some-param": "some-value"}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		result, err := (&httpOAuth2Client{
			metadata:   *setup.providerMetadata,
			httpClient: httpClient,
		}).RequestAccessToken("some-grant-type", params)

		assert.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.AccessToken)
		require.Len(t, setup.requests, 1)
		require.Equal(t, "application/x-www-form-urlencoded", setup.requests[0].Header.Get("Content-Type"))
	})
	t.Run("error", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		result, err := (&httpOAuth2Client{
			metadata:   *setup.providerMetadata,
			httpClient: httpClient,
		}).RequestAccessToken("some-grant-type", params)

		require.ErrorContains(t, err, "request access token error")
		assert.Nil(t, result)
	})
}
