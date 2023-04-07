package oidc4vci

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestNewIssuerClient(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	t.Run("empty identifier", func(t *testing.T) {
		client, err := NewIssuerClient(ctx, httpClient, "")

		require.EqualError(t, err, "empty Credential Issuer Identifier")
		require.Nil(t, client)
	})
	t.Run("error loading credential issuer metadata", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.issuerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}

		client, err := NewIssuerClient(ctx, httpClient, setup.providerMetadata.Issuer)

		require.ErrorContains(t, err, "unable to load Credential Issuer Metadata")
		require.Nil(t, client)
	})
	t.Run("error loading provider metadata", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.providerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}

		client, err := NewIssuerClient(ctx, httpClient, setup.providerMetadata.Issuer)

		require.ErrorContains(t, err, "unable to load OIDC Provider Metadata")
		require.Nil(t, client)
	})
}

func Test_httpIssuerClient_GetCredential(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	credentialRequest := CredentialRequest{
		CredentialDefinition: &map[string]interface{}{
			"issuer": "issuer",
		},
		Format: "ldp_vc",
	}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.NoError(t, err)
		require.NotNil(t, credential)
	})
	t.Run("error - no credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = setup.httpPostHandler(CredentialResponse{})
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.EqualError(t, err, "credential response does not contain a credential")
		require.Nil(t, credential)
	})
	t.Run("error - invalid credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = setup.httpPostHandler(CredentialResponse{Credential: &map[string]interface{}{
			"issuer": []string{"1", "2"}, // Invalid issuer
		}})
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.ErrorContains(t, err, "unable to unmarshal received credential: json: cannot unmarshal")
		require.Nil(t, credential)
	})
}
