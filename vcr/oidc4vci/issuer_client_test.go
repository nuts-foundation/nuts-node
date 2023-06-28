/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package oidc4vci

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestNewIssuerClient(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	t.Run("empty identifier", func(t *testing.T) {
		client, err := NewIssuerAPIClient(ctx, httpClient, "")

		require.EqualError(t, err, "empty Credential Issuer Identifier")
		require.Nil(t, client)
	})
	t.Run("credential issuer metadata", func(t *testing.T) {
		t.Run("non-OK HTTP status code", func(t *testing.T) {
			setup := setupClientTest(t)
			setup.issuerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusNotFound)
			}

			client, err := NewIssuerAPIClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)

			require.ErrorContains(t, err, "unable to load Credential Issuer Metadata")
			require.Nil(t, client)
		})
		t.Run("identifier differs", func(t *testing.T) {
			setup := setupClientTest(t)
			correctIdentifier := setup.issuerMetadata.CredentialIssuer
			setup.issuerMetadata.CredentialIssuer = "https://example.com"

			client, err := NewIssuerAPIClient(ctx, httpClient, correctIdentifier)

			require.ErrorContains(t, err, "invalid credential issuer meta data: identifier in meta data differs from requested identifier")
			require.Nil(t, client)
		})
	})

	t.Run("OpenID provider metadata", func(t *testing.T) {
		t.Run("non-OK HTTP status code", func(t *testing.T) {
			setup := setupClientTest(t)
			setup.providerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusNotFound)
			}

			client, err := NewIssuerAPIClient(ctx, httpClient, setup.providerMetadata.Issuer)

			require.ErrorContains(t, err, "unable to load OIDC Provider Metadata")
			require.Nil(t, client)
		})
		t.Run("identifier differs", func(t *testing.T) {
			setup := setupClientTest(t)
			correctIdentifier := setup.providerMetadata.Issuer
			setup.providerMetadata.Issuer = "https://example.com"

			client, err := NewIssuerAPIClient(ctx, httpClient, correctIdentifier)

			require.ErrorContains(t, err, "invalid OpenID provider meta data: issuer in meta data differs from requested issuer")
			require.Nil(t, client)
		})
	})
}

func Test_httpIssuerClient_RequestCredential(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	credentialRequest := CredentialRequest{
		CredentialDefinition: &map[string]interface{}{
			"issuer": "issuer",
		},
		Format: VerifiableCredentialJSONLDFormat,
	}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		client, err := NewIssuerAPIClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.RequestCredential(ctx, credentialRequest, "token")

		require.NoError(t, err)
		require.NotNil(t, credential)
	})
	t.Run("error - no credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = setup.httpPostHandler(CredentialResponse{})
		client, err := NewIssuerAPIClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.RequestCredential(ctx, credentialRequest, "token")

		require.EqualError(t, err, "credential response does not contain a credential")
		require.Nil(t, credential)
	})
	t.Run("error - invalid credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = setup.httpPostHandler(CredentialResponse{Credential: &map[string]interface{}{
			"issuer": []string{"1", "2"}, // Invalid issuer
		}})
		client, err := NewIssuerAPIClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.RequestCredential(ctx, credentialRequest, "token")

		require.ErrorContains(t, err, "unable to unmarshal received credential: json: cannot unmarshal")
		require.Nil(t, credential)
	})
}

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
