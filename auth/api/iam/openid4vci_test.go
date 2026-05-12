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
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core/to"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/openid4vci"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_RequestOpenid4VCICredentialIssuance(t *testing.T) {
	redirectURI := "https://test.test/iam/123/cb"
	authServer := "https://auth.server/"
	metadata := openid4vci.OpenIDCredentialIssuerMetadata{
		CredentialIssuer:     "issuer",
		CredentialEndpoint:   "endpoint",
		AuthorizationServers: []string{authServer},
		Display:              nil,
	}
	authzMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:    "https://auth.server/authorize",
		TokenEndpoint:            "https://auth.server/token",
		ClientIdSchemesSupported: clientIdSchemesSupported,
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, RequestOpenid4VCICredentialIssuanceRequestObject{
			SubjectID: holderSubjectID,
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []AuthorizationDetail{{Type: "openid_credential", CredentialConfigurationId: "UniversityDegreeCredential", Format: to.Ptr("vc+sd-jwt")}},
				Issuer:               issuerClientID,
				RedirectUri:          redirectURI,
				WalletDid:            holderDID.String(),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, response) //RequestOid4vciCredentialIssuanceResponseObject
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
		assert.Equal(t, `[{"credential_configuration_id":"UniversityDegreeCredential","format":"vc+sd-jwt","type":"openid_credential"}]`, redirectUri.Query().Get("authorization_details"))
	})
	t.Run("ok - credential_details persisted into session", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		details := map[string]interface{}{"bsn": "900184590"}
		req := requestCredentials(holderSubjectID, issuerClientID, redirectURI)
		req.Body.CredentialDetails = &details

		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		require.NoError(t, err)
		redirectUri, _ := url.Parse(response.(RequestOpenid4VCICredentialIssuance200JSONResponse).RedirectURI)
		var stored OAuthSession
		require.NoError(t, ctx.client.oauthClientStateStore().Get(redirectUri.Query().Get("state"), &stored))
		assert.Equal(t, details, stored.CredentialRequestDetails)
	})
	t.Run("openid4vciMetadata", func(t *testing.T) {
		t.Run("ok - fallback to issuerDID on empty AuthorizationServers", func(t *testing.T) {
			ctx := newTestClient(t)
			metadata := openid4vci.OpenIDCredentialIssuerMetadata{
				CredentialIssuer:     "issuer",
				CredentialEndpoint:   "endpoint",
				AuthorizationServers: []string{}, // empty
				Display:              nil,
			}
			ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, issuerClientID).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})

		t.Run("error - none of the authorization servers can be reached", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, issuerClientID).Return(nil, assert.AnError)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(nil, assert.AnError)

			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
		t.Run("error - fetching credential issuer metadata fails", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
	})
	t.Run("error - invalid issuer", func(t *testing.T) {
		req := requestCredentials(holderSubjectID, issuerClientID, redirectURI)
		req.Body.Issuer = ""
		ctx := newTestClient(t)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.EqualError(t, err, "issuer is empty")
	})
	t.Run("error - empty authorization_details", func(t *testing.T) {
		// Schema declares minItems: 1 but the StrictServer middleware does not
		// enforce array bounds at runtime; the handler must reject empty arrays
		// before any outbound metadata fetches.
		req := requestCredentials(holderSubjectID, issuerClientID, redirectURI)
		req.Body.AuthorizationDetails = []AuthorizationDetail{}
		ctx := newTestClient(t)
		// Deliberately no mock expectations: rejection must happen before
		// metadata is fetched.

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.ErrorContains(t, err, "must contain exactly one entry")
	})
	t.Run("error - multiple authorization_details", func(t *testing.T) {
		// Schema declares maxItems: 1; same StrictServer gap as minItems.
		req := requestCredentials(holderSubjectID, issuerClientID, redirectURI)
		req.Body.AuthorizationDetails = []AuthorizationDetail{
			{Type: "openid_credential", CredentialConfigurationId: "First"},
			{Type: "openid_credential", CredentialConfigurationId: "Second"},
		}
		ctx := newTestClient(t)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.ErrorContains(t, err, "must contain exactly one entry")
	})
	t.Run("error - invalid authorization endpoint in metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		invalidAuthzMetadata := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:    ":",
			TokenEndpoint:            "https://auth.server/token",
			ClientIdSchemesSupported: []string{"did"},
		}
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&invalidAuthzMetadata, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))

		assert.EqualError(t, err, "failed to parse the authorization_endpoint: parse \":\": missing protocol scheme")
	})
	t.Run("error - missing credential_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		metadata := metadata
		metadata.CredentialEndpoint = ""
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no credential_endpoint found")
	})
	t.Run("error - missing authorization_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		authzMetadata := authzMetadata
		authzMetadata.AuthorizationEndpoint = ""
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no authorization_endpoint found")
	})
	t.Run("error - missing token_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		authzMetadata := authzMetadata
		authzMetadata.TokenEndpoint = ""
		ctx.openid4vciClient.EXPECT().OpenIDCredentialIssuerMetadata(nil, issuerClientID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderSubjectID, issuerClientID, redirectURI))
		assert.EqualError(t, err, "no token_endpoint found")
	})
}

func requestCredentials(subjectID string, issuer string, redirectURI string) RequestOpenid4VCICredentialIssuanceRequestObject {
	return RequestOpenid4VCICredentialIssuanceRequestObject{
		SubjectID: subjectID,
		Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
			AuthorizationDetails: []AuthorizationDetail{{Type: "openid_credential", CredentialConfigurationId: "UniversityDegreeCredential"}},
			Issuer:               issuer,
			RedirectUri:          redirectURI,
			WalletDid:            holderDID.String(),
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
		IssuerCredentialIssuer:          issuerClientID,
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
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
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
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.Callback(nil, CallbackRequestObject{
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
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").DoAndReturn(func(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, key interface{}) (string, error) {
			_, hasNonce := claims["nonce"]
			assert.False(t, hasNonce, "nonce should not be set when no nonce endpoint is configured")
			return "signed-proof", nil
		})
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &sessionWithoutNonce)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("ok - credential_details from session forwarded to credential endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		details := map[string]any{
			"credential_identifier": "HealthCareProfessionalDelegationCredential",
			"bsn":                   "900184590",
			"ura":                   "900030757",
		}
		sessionWithDetails := session
		sessionWithDetails.CredentialRequestDetails = details
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{
			CredentialEndpoint:        credEndpoint,
			AccessToken:               accessToken,
			CredentialConfigurationID: credentialConfigID,
			ProofJWT:                  "signed-proof",
			CredentialDetails:         details,
		}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &sessionWithDetails)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("ok - invalid_nonce retry succeeds", func(t *testing.T) {
		ctx := newTestClient(t)
		freshNonce := "fresh-nonce"
		invalidNonceErr := oauth.OAuth2Error{Code: oauth.InvalidNonce}

		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		// first attempt fails with invalid_nonce
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil).Times(2)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-1", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof-1"}).Return(nil, invalidNonceErr)
		// retry with fresh nonce
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(freshNonce, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-2", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof-2"}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		require.NoError(t, err)
		assert.NotNil(t, callback)
	})
	t.Run("error - invalid_nonce retry also fails", func(t *testing.T) {
		ctx := newTestClient(t)
		invalidNonceErr := oauth.OAuth2Error{Code: oauth.InvalidNonce}

		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil).Times(2)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-1", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof-1"}).Return(nil, invalidNonceErr)
		// retry also fails
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return("fresh-nonce", nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof-2", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof-2"}).Return(nil, errors.New("still failing"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error while fetching the credential from endpoint")
	})
	t.Run("error - nonce endpoint fails during retry", func(t *testing.T) {
		ctx := newTestClient(t)
		invalidNonceErr := oauth.OAuth2Error{Code: oauth.InvalidNonce}

		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(nil, invalidNonceErr)
		// retry nonce fetch fails
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return("", errors.New("nonce endpoint down"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error fetching nonce for retry")
	})
	t.Run("ok - uses credential_identifier from token response authorization_details", func(t *testing.T) {
		ctx := newTestClient(t)
		// Per §3.3.4 / §8.2: when the AS returns authorization_details with
		// credential_identifiers, the wallet MUST send credential_identifier
		// in the Credential Request.
		tokenResponseWithAuthDetails := (&oauth.TokenResponse{AccessToken: accessToken, TokenType: "Bearer"}).
			With(oauth.AuthorizationDetailsParam, []map[string]interface{}{{
				"type":                        "openid_credential",
				"credential_configuration_id": credentialConfigID,
				"credential_identifiers":      []string{"CivilEngineeringDegree-2023"},
			}})
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponseWithAuthDetails, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{
			CredentialEndpoint:        credEndpoint,
			AccessToken:               accessToken,
			CredentialConfigurationID: credentialConfigID,
			CredentialIdentifier:      "CivilEngineeringDegree-2023",
			ProofJWT:                  "signed-proof",
		}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		require.NoError(t, err)
		require.NotNil(t, callback)
	})
	t.Run("error - authorization_details present but missing credential_identifiers", func(t *testing.T) {
		ctx := newTestClient(t)
		// Per §6.2 / §8.2: when the AS returns authorization_details for the
		// requested credential_configuration_id, credential_identifiers is
		// REQUIRED. Silent fallback to credential_configuration_id is not
		// permitted; the wallet must surface an error.
		tokenResponseWithBadDetails := (&oauth.TokenResponse{AccessToken: accessToken, TokenType: "Bearer"}).
			With(oauth.AuthorizationDetailsParam, []map[string]interface{}{{
				"type":                        "openid_credential",
				"credential_configuration_id": credentialConfigID,
				// credential_identifiers omitted
			}})
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponseWithBadDetails, nil)

		_, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential_identifiers")
	})
	t.Run("error - initial nonce request fails", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return("", errors.New("nonce endpoint unavailable"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error fetching nonce from")
	})
	t.Run("fail_access_token", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "access_denied - error while fetching the access_token from endpoint: https://auth.server/token, error: FAIL", err.Error())
	})
	t.Run("fail_credential_response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while fetching the credential from endpoint https://auth.server/credz, error: FAIL")
	})
	t.Run("err - invalid credential", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(&openid4vci.CredentialResponse{
			Credentials: []openid4vci.CredentialResponseEntry{{Credential: json.RawMessage(`"super invalid"`)}},
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "error while parsing the credential")
	})
	t.Run("fail_verify", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil).Return(errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while verifying the credential from issuer: did:web:example.com:iam:issuer, error: FAIL")
	})
	t.Run("error - key not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("", nil, resolver.ErrKeyNotFound)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to resolve key for did (did:web:example.com:iam:holder): "+resolver.ErrKeyNotFound.Error())
	})
	t.Run("error - signature failure", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("signature failed"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to sign the JWT with kid (kid): signature failed")
	})
	t.Run("error - nil OwnDID in session", func(t *testing.T) {
		ctx := newTestClient(t)
		sessionNilDID := session
		sessionNilDID.OwnDID = nil

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &sessionNilDID)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "missing wallet DID in session")
	})
	t.Run("error - empty credentials array", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderSubjectID, holderClientID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.openid4vciClient.EXPECT().RequestNonce(nil, nonceEndpoint).Return(cNonce, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("kid", nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.openid4vciClient.EXPECT().RequestCredential(nil, openid4vci.RequestCredentialOpts{CredentialEndpoint: credEndpoint, AccessToken: accessToken, CredentialConfigurationID: credentialConfigID, ProofJWT: "signed-proof"}).Return(&openid4vci.CredentialResponse{
			Credentials: []openid4vci.CredentialResponseEntry{},
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "credential response does not contain any credentials")
	})
}
