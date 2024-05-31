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
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
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
		Display:              nil,
	}
	authzMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint: "https://auth.server/authorize",
		TokenEndpoint:         "https://auth.server/token",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		response, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, RequestOpenid4VCICredentialIssuanceRequestObject{
			Did: holderDID.String(),
			Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []map[string]interface{}{{"type": "openid_credential", "format": "vc+sd-jwt"}},
				Issuer:               issuerDID.String(),
				RedirectUri:          redirectURI,
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
		assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:holder/callback", redirectUri.Query().Get("redirect_uri"))
		assert.Equal(t, holderDID.String(), redirectUri.Query().Get("client_id"))
		assert.Equal(t, "S256", redirectUri.Query().Get("code_challenge_method"))
		assert.Equal(t, "code", redirectUri.Query().Get("response_type"))
		assert.Equal(t, `[{"format":"vc+sd-jwt","type":"openid_credential"}]`, redirectUri.Query().Get("authorization_details"))
		println(redirectUri.String())
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
			ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, issuerURL).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})

		t.Run("error - none of the authorization servers can be reached", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(nil, assert.AnError)
			ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, issuerURL).Return(nil, assert.AnError)

			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
		t.Run("error - did not owned by this node", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(false, nil)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
			require.Error(t, err)
			assert.EqualError(t, err, "requester DID: DID document not managed by this node")
		})
		t.Run("error - fetching credential issuer metadata fails", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
			ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(nil, assert.AnError)
			_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
			assert.ErrorIs(t, err, assert.AnError)
		})
	})
	t.Run("error - issuer not a did", func(t *testing.T) {
		req := requestCredentials(holderDID, issuerDID, redirectURI)
		req.Body.Issuer = "not-a-did"
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.EqualError(t, err, "could not parse Issuer DID: not-a-did: invalid DID")
	})
	t.Run("error - requester not a did:web", func(t *testing.T) {
		req := requestCredentials(holderDID, issuerDID, redirectURI)
		didNuts := did.MustParseDID("did:nuts:123")
		req.Did = didNuts.String()
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, didNuts).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.ErrorContains(t, err, "URL does not represent a Web DID\nunsupported DID method: nuts")
	})
	t.Run("error - issuer not a did:web", func(t *testing.T) {
		req := requestCredentials(holderDID, issuerDID, redirectURI)
		req.Body.Issuer = "did:nuts:123"
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, req)

		assert.ErrorContains(t, err, "invalid issuer: URL does not represent a Web DID\nunsupported DID method: nuts")
	})
	t.Run("error - invalid authorization endpoint in metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		invalidAuthzMetadata := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint: ":",
			TokenEndpoint:         "https://auth.server/token"}
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&invalidAuthzMetadata, nil)

		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))

		assert.EqualError(t, err, "failed to parse the authorization_endpoint: parse \":\": missing protocol scheme")
	})
	t.Run("error - missing credential_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		metadata := metadata
		metadata.CredentialEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		assert.EqualError(t, err, "no credential_endpoint found")
	})
	t.Run("error - missing authorization_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		authzMetadata := authzMetadata
		authzMetadata.AuthorizationEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		assert.EqualError(t, err, "no authorization_endpoint found")
	})
	t.Run("error - missing token_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		authzMetadata := authzMetadata
		authzMetadata.TokenEndpoint = ""
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerURL).Return(&metadata, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(nil, authServer).Return(&authzMetadata, nil)
		_, err := ctx.client.RequestOpenid4VCICredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		assert.EqualError(t, err, "no token_endpoint found")
	})
}

func requestCredentials(holderDID did.DID, issuerDID did.DID, redirectURI string) RequestOpenid4VCICredentialIssuanceRequestObject {
	return RequestOpenid4VCICredentialIssuanceRequestObject{
		Did: holderDID.String(),
		Body: &RequestOpenid4VCICredentialIssuanceJSONRequestBody{
			Issuer:      issuerDID.String(),
			RedirectUri: redirectURI,
		},
	}
}

func TestWrapper_handleOpenID4VCICallback(t *testing.T) {
	redirectURI := "https://example.com/oauth2/did:web:example.com:iam:holder/callback"
	authServer := "https://auth.server"
	tokenEndpoint := authServer + "/token"
	cNonce := crypto.GenerateNonce()
	credEndpoint := authServer + "/credz"
	pkceParams := generatePKCEParams()
	code := "code"
	state := "state"
	accessToken := "access_token"
	verifiableCredential := createIssuerCredential(issuerDID, holderDID)
	redirectUrl := "https://client.service/issuance_is_done"

	session := OAuthSession{
		ClientFlow:               "openid4vci_credential_request",
		OwnDID:                   &holderDID,
		OtherDID:                 &issuerDID,
		RedirectURI:              redirectUrl,
		PKCEParams:               pkceParams,
		TokenEndpoint:            tokenEndpoint,
		IssuerCredentialEndpoint: credEndpoint,
	}
	tokenResponse := oauth.NewTokenResponse(accessToken, "Bearer", 0, "").With("c_nonce", cNonce)
	credentialResponse := iam.CredentialResponse{
		Credential: verifiableCredential.Raw(),
	}
	now := time.Now()
	timeFunc = func() time.Time { return now }
	defer func() { timeFunc = time.Now }()
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		require.NoError(t, ctx.client.oauthClientStateStore().Put(state, &session))
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI("kid"), nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "kid").DoAndReturn(func(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, key interface{}) (string, error) {
			assert.Equal(t, map[string]interface{}{"typ": "openid4vci-proof+jwt", "kid": "kid"}, headers)
			expectedClaims := map[string]interface{}{
				"iss":   holderDID.String(),
				"aud":   issuerURL, // must be the URL, not the DID
				"iat":   timeFunc().Unix(),
				"nonce": cNonce,
			}
			assert.Equal(t, expectedClaims, claims)
			return "signed-proof", nil
		})
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.Callback(nil, CallbackRequestObject{
			Did: holderDID.String(),
			Params: CallbackParams{
				Code:  ptrTo(code),
				State: ptrTo(state),
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, callback)
		actual := callback.(Callback302Response)
		assert.Equal(t, redirectUrl, actual.Headers.Location)
	})
	t.Run("fail_access_token", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "access_denied - error while fetching the access_token from endpoint: https://auth.server/token, error: FAIL", err.Error())
	})
	t.Run("fail_credential_response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI("kid"), nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, "signed-proof").Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while fetching the credential from endpoint https://auth.server/credz, error: FAIL")
	})
	t.Run("err - invalid credential", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI("kid"), nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, "signed-proof").Return(&iam.CredentialResponse{
			Credential: "super invalid",
		}, nil)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while parsing the credential: super invalid, error: invalid JWT")
	})
	t.Run("fail_verify", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI("kid"), nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-proof", nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, "signed-proof").Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil).Return(errors.New("FAIL"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.EqualError(t, err, "server_error - error while verifying the credential from issuer: did:web:example.com:iam:issuer, error: FAIL")
	})
	t.Run("error - key not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.URI{}, nil, resolver.ErrKeyNotFound)

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to resolve key for did (did:web:example.com:iam:holder): "+resolver.ErrKeyNotFound.Error())
	})
	t.Run("error - signature failure", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AccessToken(nil, code, tokenEndpoint, redirectURI, holderDID, pkceParams.Verifier, false).Return(tokenResponse, nil)
		ctx.keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI("kid"), nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("signature failed"))

		callback, err := ctx.client.handleOpenID4VCICallback(nil, code, &session)

		assert.Nil(t, callback)
		assert.ErrorContains(t, err, "failed to sign the JWT with kid (kid): signature failed")
	})
}
