/*
 * Copyright (C) 2024 Nuts community
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

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core/to"

	iamclient "github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_RequestOpenid4VCICredentialIssuance(t *testing.T) {
	redirectURI := "https://test.test/iam/123/cb"
	authServer := "https://auth.server/"
	metadata := oauth.OpenIDCredentialIssuerMetadata{
		CredentialIssuer:     "issuer",
		CredentialEndpoint:   "endpoint",
		AuthorizationServers: []string{authServer},
		CredentialConfigurationsSupported: map[string]map[string]interface{}{
			"NutsOrganizationCredential_ldp_vc": {"format": "ldp_vc"},
		},
		Display: nil,
	}
	authzMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:    "https://auth.server/authorize",
		TokenEndpoint:            "https://auth.server/token",
		ClientIdSchemesSupported: clientIdSchemesSupported,
	}
	t.Run("ok - locations injected when authorization_servers present", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, response)
		redirectUri, err := url.Parse(response.(RequestOpenid4VCICredentialIssuance200JSONResponse).RedirectURI)
		require.NoError(t, err)
		assert.Equal(t, "auth.server", redirectUri.Host)
		assert.Equal(t, "/authorize", redirectUri.Path)
		assert.True(t, redirectUri.Query().Has("state"))
		assert.True(t, redirectUri.Query().Has("code_challenge"))
		assert.Equal(t, "https://example.com/oauth2/holder/callback", redirectUri.Query().Get("redirect_uri"))
		assert.Equal(t, holderClientID, redirectUri.Query().Get("client_id"))
		assert.Equal(t, "S256", redirectUri.Query().Get("code_challenge_method"))
		assert.Equal(t, "code", redirectUri.Query().Get("response_type"))
		assert.Equal(t, `[{"credential_configuration_id":"NutsOrganizationCredential_ldp_vc","locations":["issuer"],"type":"openid_credential"}]`, redirectUri.Query().Get("authorization_details"))
	})
	t.Run("ok - no locations when authorization_servers absent", func(t *testing.T) {
		ctx := newTestClient(t)
		metadataNoAS := oauth.OpenIDCredentialIssuerMetadata{
			CredentialIssuer:   issuerClientID,
			CredentialEndpoint: "endpoint",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"NutsOrganizationCredential_ldp_vc": {"format": "ldp_vc"},
			},
		}
		authzMetadataLocal := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:    "https://auth.server/authorize",
			TokenEndpoint:            "https://auth.server/token",
			ClientIdSchemesSupported: clientIdSchemesSupported,
		}
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadataNoAS, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), issuerClientID).Return(&authzMetadataLocal, nil)
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		require.NoError(t, err)
		redirectUri, err := url.Parse(response.(RequestOpenid4VCICredentialIssuance200JSONResponse).RedirectURI)
		require.NoError(t, err)
		assert.Equal(t, `[{"credential_configuration_id":"NutsOrganizationCredential_ldp_vc","type":"openid_credential"}]`, redirectUri.Query().Get("authorization_details"))
	})
	t.Run("ok - unknown keys in authorization_details are stripped", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc", "evil_key": "injected"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		require.NoError(t, err)
		redirectUri, err := url.Parse(response.(RequestOpenid4VCICredentialIssuance200JSONResponse).RedirectURI)
		require.NoError(t, err)
		assert.Equal(t, `[{"credential_configuration_id":"NutsOrganizationCredential_ldp_vc","locations":["issuer"],"type":"openid_credential"}]`, redirectUri.Query().Get("authorization_details"))
	})
	t.Run("error - multiple authorization_details entries", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{
					{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"},
					{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"},
				},
				Issuer:      issuerClientID,
				RedirectUri: redirectURI,
				WalletDid:   holderDID.String(),
			},
		})
		assert.EqualError(t, err, "invalid authorization_details: exactly one entry is supported")
	})
	t.Run("error - authorization_details type is not openid_credential", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "invalid_type", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		assert.EqualError(t, err, "invalid authorization_details: type must be \"openid_credential\"")
	})
	t.Run("error - authorization_details entry missing credential_configuration_id", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		assert.EqualError(t, err, "invalid authorization_details: credential_configuration_id is required")
	})
	t.Run("error - credential_configuration_id not in issuer metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "unknown_config"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		assert.EqualError(t, err, "invalid authorization_details: credential_configuration_id \"unknown_config\" not found in issuer metadata")
	})
	t.Run("ok - uses PAR when endpoint advertised", func(t *testing.T) {
		ctx := newTestClient(t)
		parEndpoint := "https://auth.server/par"
		authzMetadataWithPAR := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:              "https://auth.server/authorize",
			TokenEndpoint:                      "https://auth.server/token",
			ClientIdSchemesSupported:           clientIdSchemesSupported,
			PushedAuthorizationRequestEndpoint: parEndpoint,
		}
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadataWithPAR, nil)
		ctx.iamClient.EXPECT().PushedAuthorizationRequest(gomock.Any(), parEndpoint, gomock.Any()).DoAndReturn(func(_ context.Context, _ string, params url.Values) (*iamclient.PARResponse, error) {
			assert.Equal(t, oauth.CodeResponseType, params.Get(oauth.ResponseTypeParam))
			assert.Equal(t, holderClientID, params.Get(oauth.ClientIDParam))
			assert.NotEmpty(t, params.Get(oauth.StateParam))
			assert.NotEmpty(t, params.Get(oauth.CodeChallengeParam))
			return &iamclient.PARResponse{RequestURI: "urn:ietf:params:oauth:request_uri:xyz", ExpiresIn: 60}, nil
		})
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, response)
		redirectUri, err := url.Parse(response.(RequestOpenid4VCICredentialIssuance200JSONResponse).RedirectURI)
		require.NoError(t, err)
		assert.Equal(t, "auth.server", redirectUri.Host)
		assert.Equal(t, "/authorize", redirectUri.Path)
		assert.Equal(t, holderClientID, redirectUri.Query().Get("client_id"))
		assert.Equal(t, "urn:ietf:params:oauth:request_uri:xyz", redirectUri.Query().Get("request_uri"))
		assert.Empty(t, redirectUri.Query().Get("state"), "state should not be in redirect when using PAR")
		assert.Empty(t, redirectUri.Query().Get("code_challenge"), "code_challenge should not be in redirect when using PAR")
	})
	t.Run("error - PAR request fails", func(t *testing.T) {
		ctx := newTestClient(t)
		parEndpoint := "https://auth.server/par"
		authzMetadataWithPAR := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:              "https://auth.server/authorize",
			TokenEndpoint:                      "https://auth.server/token",
			ClientIdSchemesSupported:           clientIdSchemesSupported,
			PushedAuthorizationRequestEndpoint: parEndpoint,
		}
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadataWithPAR, nil)
		ctx.iamClient.EXPECT().PushedAuthorizationRequest(gomock.Any(), parEndpoint, gomock.Any()).Return(nil, errors.New("PAR failed"))
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "credential_configuration_id": "NutsOrganizationCredential_ldp_vc"}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		assert.EqualError(t, err, "PAR request failed: PAR failed")
	})
	t.Run("openid4vciMetadata", func(t *testing.T) {
		t.Run("ok - fallback to issuerDID on empty AuthorizationServers", func(t *testing.T) {
			ctx := newTestClient(t)
			metadata := oauth.OpenIDCredentialIssuerMetadata{
				CredentialIssuer:     "issuer",
				CredentialEndpoint:   "endpoint",
				AuthorizationServers: []string{}, // empty
				Display:              nil,
			}
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), issuerClientID).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})

		t.Run("error - none of the authorization servers can be reached", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), issuerClientID).Return(nil, assert.AnError)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(nil, assert.AnError)

			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
		t.Run("error - fetching credential issuer metadata fails", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
	})
	t.Run("error - invalid issuer", func(t *testing.T) {
		req := requestCredentials(holderSubjectID, issuerClientID, redirectURI)
		req.Body.Issuer = ""
		ctx := newTestClient(t)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), req)

		assert.EqualError(t, err, "issuer is empty")
	})
	t.Run("error - invalid authorization endpoint in metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		invalidAuthzMetadata := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:    ":",
			TokenEndpoint:            "https://auth.server/token",
			ClientIdSchemesSupported: []string{"did"},
		}
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&invalidAuthzMetadata, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))

		assert.EqualError(t, err, "failed to parse the authorization_endpoint: parse \":\": missing protocol scheme")
	})
	t.Run("error - missing credential_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		metadata := metadata
		metadata.CredentialEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no credential_endpoint found")
	})
	t.Run("error - missing authorization_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		authzMetadata := authzMetadata
		authzMetadata.AuthorizationEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no authorization_endpoint found")
	})
	t.Run("error - missing token_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		authzMetadata := authzMetadata
		authzMetadata.TokenEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(gomock.Any(), issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(context.Background(), requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no token_endpoint found")
	})
}

func requestCredentials(subjectID string, issuer string, redirectURI string) RequestOpenid4VCICredentialIssuanceRequestObject {
	return RequestOpenid4VCICredentialIssuanceRequestObject{
		SubjectID: subjectID,
		Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
			Issuer:      issuer,
			RedirectUri: redirectURI,
			WalletDid:   holderDID.String(),
		},
	}
}

func TestWrapper_handleOpenID4VCICallback(t *testing.T) {
	redirectURI := "https://example.com/oauth2/holder/callback"
	authServer := "https://auth.server"
	tokenEndpoint := authServer + "/token"
	nonceEndpoint := authServer + "/nonce"
	cNonce := crypto.GenerateNonce()
	credEndpoint := authServer + "/credz"
	pkceParams := generatePKCEParams()
	code := "code"
	state := "state"
	accessToken := "access_token"
	verifiableCredential := createIssuerCredential(issuerDID, holderDID)
	redirectUrl := "https://client.service/issuance_is_done"

	credentialConfigID := "NutsOrganizationCredential_ldp_vc"
	session := OAuthSession{
		AuthorizationServerMetadata: &oauth.AuthorizationServerMetadata{
			ClientIdSchemesSupported: clientIdSchemesSupported,
		},
		ClientFlow:                      "openid4vci_credential_request",
		OwnSubject:                      &holderSubjectID,
		OwnDID:                          &holderDID,
		RedirectURI:                     redirectUrl,
		PKCEParams:                      pkceParams,
		TokenEndpoint:                   tokenEndpoint,
		IssuerURL:                       issuerClientID,
		IssuerCredentialEndpoint:        credEndpoint,
		IssuerNonceEndpoint:             nonceEndpoint,
		IssuerCredentialConfigurationID: credentialConfigID,
	}
	sessionWithoutNonce := session
	sessionWithoutNonce.IssuerNonceEndpoint = ""

	tokenResponse := &oauth.TokenResponse{AccessToken: accessToken, TokenType: "Bearer"}
	credentialResponse := openid4vci.CredentialResponse{
		Credentials: []openid4vci.CredentialResponseEntry{{Credential: json.RawMessage(verifiableCredential.Raw())}},
	}
	now := time.Now()
	timeFunc = func() time.Time { return now }
	defer func() { timeFunc = time.Now }()
	t.Run("ok - with nonce endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		require.NoError(t, ctx.client.oauthClientStateStore().Put(state, &session))
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").DoAndReturn(func(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, key interface{}) (string, error) {
			assert.Equal(t, map[string]interface{}{"typ": "openid4vci-proof+jwt", "kid": "kid"}, headers)
			expectedClaims := map[string]interface{}{
				"iss":   holderDID.String(),
				"aud":   issuerURL.String(),
				"iat":   timeFunc().Unix(),
				"nonce": cNonce,
			}
			assert.Equal(t, expectedClaims, claims)
			return "signed-proof", nil
		})
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.Callback(context.Background(), CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				Code:  to.Ptr(code),
				State: to.Ptr(state),
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, callback)
		actual := callback.(Callback302Response)
		assert.Equal(t, redirectUrl, actual.Headers.Location)
	})
	t.Run("ok - no nonce endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").DoAndReturn(func(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, key interface{}) (string, error) {
			_, hasNonce := claims["nonce"]
			assert.False(t, hasNonce, "nonce should not be set when no nonce endpoint is configured")
			return "signed-proof", nil
		})
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &sessionWithoutNonce)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("ok - invalid_nonce retry succeeds", func(t *testing.T) {
		ctx := newTestClient(t)
		freshNonce := "fresh-nonce"
		invalidNonceErr := openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: 400}

		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		// first attempt fails with invalid_nonce
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil).Times(2)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-1", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof-1").Return(nil, invalidNonceErr)
		// retry with fresh nonce
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(freshNonce, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-2", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof-2").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("error - invalid_nonce retry also fails", func(t *testing.T) {
		ctx := newTestClient(t)
		invalidNonceErr := openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: 400}

		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil).Times(2)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-1", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof-1").Return(nil, invalidNonceErr)
		// retry also fails
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return("fresh-nonce", nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-2", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof-2").Return(nil, errors.New("still failing"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error while fetching the credential from endpoint")
	})
	t.Run("error - nonce endpoint fails during retry", func(t *testing.T) {
		ctx := newTestClient(t)
		invalidNonceErr := openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: 400}

		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(nil, invalidNonceErr)
		// retry nonce fetch fails
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return("", errors.New("nonce endpoint down"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error fetching nonce for retry")
	})
	t.Run("error - initial nonce request fails", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return("", errors.New("nonce endpoint unavailable"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error fetching nonce from")
	})
	t.Run("fail_access_token", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "access_denied - error while fetching the access_token from endpoint: https://auth.server/token, error: FAIL", err.Error())
	})
	t.Run("fail_credential_response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while fetching the credential from endpoint https://auth.server/credz, error: FAIL")
	})
	t.Run("err - invalid credential", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&openid4vci.CredentialResponse{
			Credentials: []openid4vci.CredentialResponseEntry{{Credential: json.RawMessage(`"super invalid"`)}},
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error while parsing the credential")
	})
	t.Run("fail_verify", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil).Return(errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while verifying the credential from issuer: did:web:example.com:iam:issuer, error: FAIL")
	})
	t.Run("error - key not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("", nil, resolver.ErrKeyNotFound)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to resolve key for did (did:web:example.com:iam:holder): "+resolver.ErrKeyNotFound.Error())
	})
	t.Run("error - signature failure", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("signature failed"))

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to sign the JWT with kid (kid): signature failed")
	})
	t.Run("error - nil OwnDID in session", func(t *testing.T) {
		ctx := newTestClient(t)
		sessionNilDID := session
		sessionNilDID.OwnDID = nil

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &sessionNilDID)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "missing wallet DID in session")
	})
	t.Run("error - signing algorithm not supported by issuer", func(t *testing.T) {
		ctx := newTestClient(t)
		p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sessionAlgMismatch := session
		sessionAlgMismatch.ProofSigningAlgValuesSupported = []string{"ES384"}

		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", &p256Key.PublicKey, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &sessionAlgMismatch)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "signing algorithm ES256 is not supported by issuer (supported: ES384)")
	})
	t.Run("ok - algorithm validation skipped when proof_signing_alg_values_supported absent", func(t *testing.T) {
		ctx := newTestClient(t)
		sessionNoAlg := session
		sessionNoAlg.ProofSigningAlgValuesSupported = nil

		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &sessionNoAlg)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("error - deferred issuance not supported", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&openid4vci.CredentialResponse{
			TransactionID: "txn-456",
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "deferred credential issuance is not supported")
	})
	t.Run("error - empty credentials array", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&openid4vci.CredentialResponse{
			Credentials: []openid4vci.CredentialResponseEntry{},
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "credential response does not contain any credentials")
	})
	t.Run("ok - uses credential_identifier from token response when present", func(t *testing.T) {
		ctx := newTestClient(t)
		tokenResponseWithIdentifier := &oauth.TokenResponse{AccessToken: accessToken, TokenType: "Bearer"}
		tokenResponseWithIdentifier.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": credentialConfigID,
				"credential_identifiers":      []interface{}{"cred-id-1", "cred-id-2"},
			},
		})
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponseWithIdentifier, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, "", "cred-id-1", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("ok - falls back to credential_configuration_id when no credential_identifiers", func(t *testing.T) {
		ctx := newTestClient(t)
		tokenResponseNoIdentifiers := &oauth.TokenResponse{AccessToken: accessToken, TokenType: "Bearer"}
		tokenResponseNoIdentifiers.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": credentialConfigID,
			},
		})
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponseNoIdentifiers, nil)
		ctx.iamClient.EXPECT().RequestNonce(gomock.Any(), nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(gomock.Any(), credEndpoint, accessToken, credentialConfigID, "", "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(gomock.Any(), *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(context.Background(), code, &session)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
}

func TestExtractCredentialIdentifier(t *testing.T) {
	t.Run("returns first identifier from openid_credential entry", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                   "openid_credential",
				"credential_identifiers": []interface{}{"id-1", "id-2"},
			},
		})

		assert.Equal(t, "id-1", extractCredentialIdentifier(tokenResponse))
	})
	t.Run("skips non-openid_credential entries", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                   "other_type",
				"credential_identifiers": []interface{}{"wrong"},
			},
			map[string]interface{}{
				"type":                   "openid_credential",
				"credential_identifiers": []interface{}{"correct"},
			},
		})

		assert.Equal(t, "correct", extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when authorization_details missing", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when authorization_details is not an array", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", "not-an-array")

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when credential_identifiers missing", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type": "openid_credential",
			},
		})

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when credential_identifiers is empty", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                   "openid_credential",
				"credential_identifiers": []interface{}{},
			},
		})

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when identifier is not a string", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{
			map[string]interface{}{
				"type":                   "openid_credential",
				"credential_identifiers": []interface{}{42},
			},
		})

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
	t.Run("returns empty when entry is not a map", func(t *testing.T) {
		tokenResponse := &oauth.TokenResponse{}
		tokenResponse.With("authorization_details", []interface{}{"not-a-map"})

		assert.Empty(t, extractCredentialIdentifier(tokenResponse))
	})
}
