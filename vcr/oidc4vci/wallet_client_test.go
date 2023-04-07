package oidc4vci

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"testing"
)

func TestNewWalletClient(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)

		client, err := NewWalletClient(ctx, httpClient, setup.walletMetadataURL)

		require.NoError(t, err)
		require.NotNil(t, client)
	})
	t.Run("empty metadata URL", func(t *testing.T) {
		client, err := NewWalletClient(ctx, httpClient, "")

		require.EqualError(t, err, "empty wallet metadata URL")
		require.Nil(t, client)
	})
	t.Run("error loading wallet metadata", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.walletMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}

		client, err := NewWalletClient(ctx, httpClient, setup.walletMetadataURL)

		require.ErrorContains(t, err, "unable to load OAuth2 credential client metadata")
		require.Nil(t, client)
	})
}

func Test_httpWalletClient_OfferCredential(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		client, err := NewWalletClient(ctx, httpClient, setup.walletMetadataURL)
		require.NoError(t, err)

		err = client.OfferCredential(ctx, CredentialOffer{
			CredentialIssuer: setup.issuerMetadata.CredentialIssuer,
			Credentials:      []map[string]interface{}{{"issuer": "issuer"}},
			Grants: []map[string]interface{}{
				{
					"grant_type": "pre-authorized_code",
				},
			},
		})

		require.NoError(t, err)
		require.Len(t, setup.requests, 2) // 1 loading metadata, 1 offering credential
		// Assert credential offer
		credentialOfferEscaped := setup.requests[1].URL.Query().Get("credential_offer")
		require.NotEmpty(t, credentialOfferEscaped)
		credentialOfferJSON, err := url.QueryUnescape(credentialOfferEscaped)
		require.NoError(t, err)
		var credentialOffer map[string]interface{}
		err = json.Unmarshal([]byte(credentialOfferJSON), &credentialOffer)
		require.NoError(t, err)
		require.Equal(t, setup.issuerMetadata.CredentialIssuer, credentialOffer["credential_issuer"])
		require.Equal(t, []interface{}{map[string]interface{}{"issuer": "issuer"}}, credentialOffer["credentials"])
		require.Equal(t, []interface{}{map[string]interface{}{"grant_type": "pre-authorized_code"}}, credentialOffer["grants"])
	})
	t.Run("error", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialOfferHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		}
		client, err := NewWalletClient(ctx, httpClient, setup.walletMetadataURL)
		require.NoError(t, err)

		err = client.OfferCredential(ctx, CredentialOffer{
			CredentialIssuer: setup.issuerMetadata.CredentialIssuer,
			Credentials:      []map[string]interface{}{{"issuer": "issuer"}},
			Grants: []map[string]interface{}{
				{
					"grant_type": "pre-authorized_code",
				},
			},
		})

		require.ErrorContains(t, err, "offer credential error")
	})
}
