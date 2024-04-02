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

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var holderDID = did.MustParseDID("did:web:example.com:iam:holder")
var issuerDID = did.MustParseDID("did:web:example.com:iam:issuer")

func TestWrapper_handleAuthorizeRequestFromHolder(t *testing.T) {
	defaultParams := func() oauthParameters {
		return map[string]interface{}{
			oauth.ClientIDParam:            holderDID.String(),
			oauth.RedirectURIParam:         "https://example.com",
			oauth.ResponseTypeParam:        "code",
			oauth.ScopeParam:               "test",
			oauth.StateParam:               "state",
			jwt.AudienceKey:                []string{verifierDID.String()},
			jwt.IssuerKey:                  holderDID.String(),
			oauth.NonceParam:               "nonce",
			oauth.CodeChallengeParam:       "code_challenge",
			oauth.CodeChallengeMethodParam: "S256",
		}
	}

	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[oauth.ClientIDParam] = "did:nuts:1"

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)")
	})
	t.Run("invalid redirect_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[oauth.RedirectURIParam] = ":/"

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid redirect_uri parameter")
	})
	t.Run("missing redirect_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, oauth.RedirectURIParam)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "missing redirect_uri parameter")
	})
	t.Run("missing audience", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, jwt.AudienceKey)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid audience, verifier = did:web:example.com:iam:verifier, audience = ")
	})
	t.Run("missing did in supported_client_id_schemes", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:    "http://example.com",
			ClientIdSchemesSupported: []string{"not_did"},
		}, nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "wallet metadata does not contain did in client_id_schemes_supported")
	})
	t.Run("missing code_challenge", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, oauth.CodeChallengeParam)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "missing code_challenge parameter")

	})
	t.Run("missing code_challenge_method", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, oauth.CodeChallengeMethodParam)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid value for code_challenge_method parameter, only S256 is supported")
	})
	t.Run("error on authorization server metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(nil, assert.AnError)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.ServerError, "failed to get metadata from wallet")
	})
}

func TestWrapper_handleAuthorizeRequestFromVerifier(t *testing.T) {
	responseURI := "https://example.com/iam/verifier/response"
	clientMetadata := oauth.OAuthClientMetadata{
		VPFormats: oauth.DefaultOpenIDSupportedFormats(),
	}
	pdEndpoint := "https://example.com/iam/verifier/presentation_definition?scope=test"
	defaultParams := func() map[string]interface{} {
		return map[string]interface{}{
			oauth.ClientIDParam:     verifierDID.String(),
			clientIDSchemeParam:     didScheme,
			clientMetadataURIParam:  "https://example.com/.well-known/authorization-server/iam/verifier",
			oauth.NonceParam:        "nonce",
			presentationDefUriParam: "https://example.com/iam/verifier/presentation_definition?scope=test",
			responseModeParam:       responseModeDirectPost,
			responseURIParam:        responseURI,
			oauth.ResponseTypeParam: responseTypeVPToken,
			oauth.ScopeParam:        "test",
			oauth.StateParam:        "state",
		}
	}
	session := OAuthSession{
		SessionID:   "token",
		OwnDID:      &holderDID,
		RedirectURI: "https://example.com/iam/holder/cb",
		VerifierDID: &verifierDID,
	}

	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[oauth.ClientIDParam] = "did:nuts:1"
		expectPostError(t, ctx, oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("invalid client_id_scheme", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[clientIDSchemeParam] = "other"
		expectPostError(t, ctx, oauth.InvalidRequest, "invalid client_id_scheme parameter", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("invalid client_metadata_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, "failed to get client metadata (verifier)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("missing nonce", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, oauth.NonceParam)
		expectPostError(t, ctx, oauth.InvalidRequest, "missing nonce parameter", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("fetching client metadata failed", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, "failed to get client metadata (verifier)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("missing response_mode", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseModeParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		assert.EqualError(t, err, "invalid_request - invalid response_mode parameter")
	})
	t.Run("missing response_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseURIParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		assert.EqualError(t, err, "invalid_request - missing response_uri parameter")
	})
	t.Run("missing state and missing response_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseURIParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.Error(t, err)
	})
	t.Run("invalid presentation_definition_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, session)
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.InvalidPresentationDefinitionURI, "failed to retrieve presentation definition on https://example.com/iam/verifier/presentation_definition?scope=test", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("failed to create verifiable presentation", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, session)
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(&pe.PresentationDefinition{}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, gomock.Any()).Return(nil, nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, assert.AnError.Error(), responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
	t.Run("missing credentials in wallet", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, session)
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(&pe.PresentationDefinition{}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, gomock.Any()).Return(nil, nil, holder.ErrNoCredentials)
		expectPostError(t, ctx, oauth.InvalidRequest, "no credentials available", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params, pe.WalletOwnerOrganization)

		require.NoError(t, err)
	})
}

func TestWrapper_HandleAuthorizeResponse(t *testing.T) {
	walletOwnerMapping := pe.WalletOwnerMapping{
		pe.WalletOwnerOrganization: pe.PresentationDefinition{
			Id: "1",
			InputDescriptors: []*pe.InputDescriptor{
				{Id: "1", Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}},
			},
		},
	}
	session := OAuthSession{
		SessionID:   "token",
		OwnDID:      &verifierDID,
		RedirectURI: "https://example.com/iam/holder/cb",
		Scope:       "test",
		ClientState: "client-state",
		OpenID4VPVerifier: &OpenID4VPVerifier{
			WalletDID:                       holderDID,
			RequiredPresentationDefinitions: walletOwnerMapping,
			Submissions:                     map[string]pe.PresentationSubmission{},
			Credentials:                     map[string]vc.VerifiableCredential{},
		},
	}
	t.Run("submission", func(t *testing.T) {
		challenge := "challenge"
		// simple vp
		vpToken := `{"type":"VerifiablePresentation", "verifiableCredential":{"type":"VerifiableCredential", "credentialSubject":{"id":"did:web:example.com:iam:holder"}},"proof":{"challenge":"challenge","domain":"did:web:example.com:iam:verifier","proofPurpose":"assertionMethod","type":"JsonWebSignature2020","verificationMethod":"did:web:example.com:iam:holder#0"}}`
		// simple submission
		submissionAsStr := `{"id":"1", "definition_id":"1", "descriptor_map":[{"id":"1","format":"ldp_vc","path":"$.verifiableCredential"}]}`
		// simple request
		state := "state"
		baseRequest := func() HandleAuthorizeResponseRequestObject {
			return HandleAuthorizeResponseRequestObject{
				Body: &HandleAuthorizeResponseFormdataRequestBody{
					VpToken:                &vpToken,
					PresentationSubmission: &submissionAsStr,
					State:                  &state,
				},
				Did: verifierDID.String(),
			}
		}
		t.Run("ok", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), gomock.Any(), "test").Return(walletOwnerMapping, nil)
			ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Return(nil, nil)

			response, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			require.NoError(t, err)
			redirectURI, _ := url.Parse(response.(HandleAuthorizeResponse200JSONResponse).RedirectURI)
			assert.True(t, strings.HasPrefix(redirectURI.String(), "https://example.com/iam/holder/cb?code"))
			assert.True(t, redirectURI.Query().Has("code"))
			assert.Equal(t, "client-state", redirectURI.Query().Get("state"))
		})
		t.Run("failed to verify vp", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), gomock.Any(), "test").Return(walletOwnerMapping, nil)
			ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Return(nil, assert.AnError)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			oauthErr := assertOAuthError(t, err, "presentation(s) or contained credential(s) are invalid")
			assert.Equal(t, "https://example.com/iam/holder/cb", oauthErr.RedirectURI.String())
		})
		t.Run("expired nonce", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			_ = assertOAuthError(t, err, "invalid or expired nonce")
		})
		t.Run("missing challenge in proof", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			request := baseRequest()
			proof := `{"proof":{}}`
			request.Body.VpToken = &proof
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "failed to extract nonce from vp_token")
		})
		t.Run("unknown verifier id", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(false, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			_ = assertOAuthError(t, err, "unknown verifier id")
		})
		t.Run("invalid vp_token", func(t *testing.T) {
			ctx := newTestClient(t)
			request := baseRequest()
			invalidToken := "}"
			request.Body.VpToken = &invalidToken
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "invalid vp_token")
		})
		t.Run("missing vp_token", func(t *testing.T) {
			ctx := newTestClient(t)
			request := baseRequest()
			request.Body.VpToken = nil
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "missing vp_token")
		})
		t.Run("invalid presentation_submission", func(t *testing.T) {
			ctx := newTestClient(t)
			request := baseRequest()
			submission := "}"
			request.Body.PresentationSubmission = &submission
			putState(ctx, session)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "invalid presentation_submission: invalid character '}' looking for beginning of value")
		})
		t.Run("missing presentation_submission", func(t *testing.T) {
			ctx := newTestClient(t)
			request := baseRequest()
			request.Body.PresentationSubmission = nil
			putState(ctx, session)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "missing presentation_submission")
		})
		t.Run("invalid signer", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			request := baseRequest()
			vpToken := `{"type":"VerifiablePresentation", "verifiableCredential":{"type":"VerifiableCredential", "credentialSubject":{}},"proof":{"challenge":"challenge","domain":"did:web:example.com:iam:verifier","proofPurpose":"assertionMethod","type":"JsonWebSignature2020","verificationMethod":"did:web:example.com:iam:holder#0"}}`
			request.Body.VpToken = &vpToken
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
		})
		t.Run("invalid audience/domain", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			request := baseRequest()
			vpToken := `{"type":"VerifiablePresentation", "verifiableCredential":{"type":"VerifiableCredential", "credentialSubject":{"id":"did:web:example.com:iam:holder"}},"proof":{"challenge":"challenge","proofPurpose":"assertionMethod","type":"JsonWebSignature2020","verificationMethod":"did:web:example.com:iam:holder#0"}}`
			request.Body.VpToken = &vpToken
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "presentation audience/domain is missing or does not match")
		})
		t.Run("submission does not match definition", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, session)
			putNonce(ctx, challenge)
			request := baseRequest()
			submission := `{"id":"1", "definition_id":"2", "descriptor_map":[{"id":"2","format":"ldp_vc","path":"$.verifiableCredential"}]}`
			request.Body.PresentationSubmission = &submission
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), gomock.Any(), "test").Return(walletOwnerMapping, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "presentation submission does not conform to Presentation Definition")
		})
	})
	t.Run("error", func(t *testing.T) {
		code := string(oauth.InvalidRequest)
		description := "error description"
		state := "state"
		baseRequest := func() HandleAuthorizeResponseRequestObject {
			return HandleAuthorizeResponseRequestObject{
				Body: &HandleAuthorizeResponseFormdataRequestBody{
					Error:            &code,
					ErrorDescription: &description,
					State:            &state,
				},
				Did: verifierDID.String(),
			}
		}
		t.Run("with client state", func(t *testing.T) {
			ctx := newTestClient(t)
			sessionWithClientState := session
			sessionWithClientState.ClientState = "client state"
			putState(ctx, sessionWithClientState)

			response, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			require.NoError(t, err)
			redirectURI := response.(HandleAuthorizeResponse200JSONResponse).RedirectURI
			assert.Contains(t, redirectURI, "https://example.com/iam/holder/cb?error=invalid_request&error_description=error+description")
		})
		t.Run("without client state", func(t *testing.T) {
			ctx := newTestClient(t)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			require.Error(t, err)
			_ = assertOAuthError(t, err, "error description")
		})
	})
}

func Test_handleAccessTokenRequest(t *testing.T) {
	redirectURI := "https://example.com/iam/holder/cb"
	code := "code"
	clientID := "did:web:example.com:iam:holder"
	vpStr := `{"type":"VerifiablePresentation", "id":"vp", "verifiableCredential":{"type":"VerifiableCredential", "id":"vc", "credentialSubject":{"id":"did:web:example.com:iam:holder"}}}`
	vp, err := vc.ParseVerifiablePresentation(vpStr)
	require.NoError(t, err)
	walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{InputDescriptors: []*pe.InputDescriptor{
		{Id: "1", Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}},
	}},
	}
	submissionAsStr := `{"id":"1", "definition_id":"1", "descriptor_map":[{"id":"1","format":"ldp_vc","path":"$.verifiableCredential"}]}`
	var submission pe.PresentationSubmission
	_ = json.Unmarshal([]byte(submissionAsStr), &submission)
	validSession := OAuthSession{
		ClientID:    clientID,
		OwnDID:      &verifierDID,
		RedirectURI: redirectURI,
		Scope:       "scope",
		OpenID4VPVerifier: &OpenID4VPVerifier{
			WalletDID:                       did.MustParseDID(clientID),
			RequiredPresentationDefinitions: nil,
			Submissions: map[string]pe.PresentationSubmission{
				string(pe.WalletOwnerOrganization): submission,
			},
			Presentations: []vc.VerifiablePresentation{*vp},
		},
		PKCEParams: generatePKCEParams(),
	}
	requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID, CodeVerifier: &validSession.PKCEParams.Verifier}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), verifierDID, "scope").Return(walletOwnerMapping, nil)
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID, CodeVerifier: &validSession.PKCEParams.Verifier}
		putCodeSession(ctx, code, validSession)

		response, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		require.NoError(t, err)
		token, ok := response.(HandleTokenRequest200JSONResponse)
		require.True(t, ok)
		assert.NotEmpty(t, token.AccessToken)
		assert.Equal(t, "bearer", token.TokenType)
		assert.Equal(t, 900, *token.ExpiresIn)
		assert.Equal(t, "scope", *token.Scope)

	})
	t.Run("invalid authorization code", func(t *testing.T) {
		ctx := newTestClient(t)
		putCodeSession(ctx, code, validSession)
		verifier := "verifier"
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID, CodeVerifier: &verifier}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		require.Error(t, err)
		oauthErr, ok := err.(oauth.OAuth2Error)
		require.True(t, ok, "expected oauth error")
		assert.Equal(t, oauth.InvalidGrant, oauthErr.Code)
		assert.Equal(t, "invalid code_verifier", oauthErr.Description)
	})
	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		putCodeSession(ctx, code, validSession)
		clientID := "other"
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID, CodeVerifier: &validSession.PKCEParams.Verifier}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		_ = assertOAuthError(t, err, "client_id does not match: did:web:example.com:iam:holder vs other")
	})
	t.Run("presentation definition backend server error", func(t *testing.T) {
		ctx := newTestClient(t)
		putCodeSession(ctx, code, validSession)
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), verifierDID, "scope").Return(nil, assert.AnError)

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		require.Error(t, err)
		oauthErr, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.ServerError, oauthErr.Code)
		assert.Equal(t, "failed to fetch presentation definition: assert.AnError general error for testing", oauthErr.Description)
	})
	t.Run("missing code", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody := HandleTokenRequestFormdataRequestBody{ClientId: &clientID, CodeVerifier: &validSession.PKCEParams.Verifier}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		_ = assertOAuthError(t, err, "missing code parameter")
	})
	t.Run("missing code_verifier", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		_ = assertOAuthError(t, err, "missing code_verifier parameter")
	})
	t.Run("expired session", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, ClientId: &clientID, CodeVerifier: &validSession.PKCEParams.Verifier}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		require.Error(t, err)
		oauthErr, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidGrant, oauthErr.Code)
		assert.Equal(t, "invalid authorization code", oauthErr.Description)
	})
	t.Run("missing client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody := HandleTokenRequestFormdataRequestBody{Code: &code, CodeVerifier: &validSession.PKCEParams.Verifier}

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), requestBody)

		_ = assertOAuthError(t, err, "missing client_id parameter")
	})
}

func Test_handleCallback(t *testing.T) {
	code := "code"
	state := "state"

	session := OAuthSession{
		SessionID:   "token",
		OwnDID:      &holderDID,
		RedirectURI: "https://example.com/iam/holder/cb",
		VerifierDID: &verifierDID,
		PKCEParams:  generatePKCEParams(),
	}

	t.Run("err - missing state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				Code: &code,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing state parameter")
	})
	t.Run("err - expired state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid or expired state")
	})
	t.Run("err - missing code", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, session)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing code parameter")
	})
	t.Run("err - failed to retrieve access token", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, session)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, verifierDID, "https://example.com/oauth2/"+webDID.String()+"/callback", holderDID, codeVerifier).Return(nil, assert.AnError)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.ServerError, "failed to retrieve access token: assert.AnError general error for testing")
	})
}

func Test_validatePresentationNonce(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		vpStr := `{"@context":["https://www.w3.org/2018/credentials/v1","https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"],"proof":{"challenge":"1"}}`
		vp, err := vc.ParseVerifiablePresentation(vpStr)
		require.NoError(t, err)
		vps := []vc.VerifiablePresentation{*vp, *vp}
		ctx := newTestClient(t)
		putNonce(ctx, "1")

		// call also burns the nonce
		err = ctx.client.validatePresentationNonce(vps)

		require.NoError(t, err)
		err = ctx.client.oauthNonceStore().Get("1", nil)
		assert.Equal(t, storage.ErrNotFound, err)
	})
	t.Run("different nonce", func(t *testing.T) {
		vpStr1 := `{"@context":["https://www.w3.org/2018/credentials/v1","https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"],"proof":{"challenge":"1"}}`
		vpStr2 := `{"@context":["https://www.w3.org/2018/credentials/v1","https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"],"proof":{"challenge":"2"}}`
		vp1, err := vc.ParseVerifiablePresentation(vpStr1)
		require.NoError(t, err)
		vp2, err := vc.ParseVerifiablePresentation(vpStr2)
		require.NoError(t, err)
		vps := []vc.VerifiablePresentation{*vp1, *vp2}
		ctx := newTestClient(t)
		putNonce(ctx, "1")
		putNonce(ctx, "2")

		// call also burns the nonce
		err = ctx.client.validatePresentationNonce(vps)

		assert.EqualError(t, err, "invalid_request - not all presentations have the same nonce")
		err = ctx.client.oauthNonceStore().Get("1", nil)
		assert.Equal(t, storage.ErrNotFound, err)
		err = ctx.client.oauthNonceStore().Get("2", nil)
		assert.Equal(t, storage.ErrNotFound, err)
	})
}

// expectPostError is a convenience method to add an expectation to the iamClient mock.
// it checks if the right error is posted to the verifier.
func expectPostError(t *testing.T, ctx *testCtx, errorCode oauth.ErrorCode, description string, expectedResponseURI string, verifierClientState string) {
	ctx.iamClient.EXPECT().PostError(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, err oauth.OAuth2Error, responseURI string, state string) (string, error) {
		assert.Equal(t, errorCode, err.Code)
		assert.Equal(t, description, err.Description)
		assert.Equal(t, expectedResponseURI, responseURI)
		assert.Equal(t, verifierClientState, state)
		holderURL, _ := createOAuth2BaseURL(holderDID)
		require.NotNil(t, holderURL)
		return holderURL.JoinPath("callback").String(), nil
	})
}

func TestWrapper_sendAndHandleDirectPost(t *testing.T) {
	t.Run("failed to post response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().PostAuthorizationResponse(gomock.Any(), gomock.Any(), gomock.Any(), "response", "").Return("", assert.AnError)

		_, err := ctx.client.sendAndHandleDirectPost(context.Background(), walletDID, vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "response", "")

		assert.Equal(t, assert.AnError, err)
	})
}

func TestWrapper_sendAndHandleDirectPostError(t *testing.T) {
	t.Run("failed to post error with redirect available", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().PostError(gomock.Any(), gomock.Any(), "response", "state").Return("", assert.AnError)
		redirectURI := test.MustParseURL("https://example.com/redirect")
		expected := HandleAuthorizeRequest302Response{
			Headers: HandleAuthorizeRequest302ResponseHeaders{
				Location: "https://example.com/redirect?error=server_error&error_description=failed+to+post+error+to+verifier+%40+response",
			},
		}

		redirect, err := ctx.client.sendAndHandleDirectPostError(context.Background(), oauth.OAuth2Error{RedirectURI: redirectURI}, "response", "state")

		require.NoError(t, err)
		assert.Equal(t, expected, redirect)
	})
	t.Run("failed to post error without redirect available", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().PostError(gomock.Any(), gomock.Any(), "response", "state").Return("", assert.AnError)

		_, err := ctx.client.sendAndHandleDirectPostError(context.Background(), oauth.OAuth2Error{}, "response", "state")

		require.Error(t, err)
		require.Equal(t, "server_error - something went wrong", err.Error())
	})
}

func Test_extractChallenge(t *testing.T) {
	t.Run("JSON-LD", func(t *testing.T) {
		vpStr :=
			`
{
	"@context":["https://www.w3.org/2018/credentials/v1","https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"],
	"proof":{
		"challenge":"86OZCbJWV4-V7XPAiXu-Rg"
	}
}
`
		// remove whitespace, tabs and newlines first otherwise the parsing doesn't know the format
		vpStr = strings.ReplaceAll(vpStr, "\n", "")
		vpStr = strings.ReplaceAll(vpStr, "\t", "")
		vpStr = strings.ReplaceAll(vpStr, " ", "")
		vp, err := vc.ParseVerifiablePresentation(vpStr)
		require.NoError(t, err)
		require.NotNil(t, vp)

		challenge, err := extractChallenge(*vp)

		require.NoError(t, err)
		assert.Equal(t, "86OZCbJWV4-V7XPAiXu-Rg", challenge)
	})

	t.Run("JWT", func(t *testing.T) {
		jwt := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpudXRzOkd2a3p4c2V6SHZFYzhuR2hnejZYbzNqYnFrSHdzd0xtV3czQ1l0Q203aEFXI2FiYy1tZXRob2QtMSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkaWQ6bnV0czpHdmt6eHNlekh2RWM4bkdoZ3o2WG8zamJxa0h3c3dMbVd3M0NZdENtN2hBVyM5NDA0NTM2Mi0zYjEyLTQyODUtYTJiNi0wZDAzZDQ0NzBkYTciLCJuYmYiOjE3MDUzMTEwNTQsIm5vbmNlIjoibm9uY2UiLCJzdWIiOiJkaWQ6bnV0czpHdmt6eHNlekh2RWM4bkdoZ3o2WG8zamJxa0h3c3dMbVd3M0NZdENtN2hBVyIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL251dHMubmwvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL2xkcy1qd3MyMDIwL2NvbnRleHRzL2xkcy1qd3MyMDIwLXYxLmpzb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY29tcGFueSI6eyJjaXR5IjoiSGVuZ2VsbyIsIm5hbWUiOiJEZSBiZXN0ZSB6b3JnIn0sImlkIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcifSwiaWQiOiJkaWQ6bnV0czo0dHpNYVdmcGl6VktlQThmc2NDM0pUZFdCYzNhc1VXV01qNWhVRkhkV1gzSCNjOWJmZmE5OC1jOGViLTQ4YzItOTIwYy1mNjk5NjEyY2Q0NjUiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTEyLTI0VDEzOjIxOjI5LjA4NzIwNSswMTowMCIsImlzc3VlciI6ImRpZDpudXRzOjR0ek1hV2ZwaXpWS2VBOGZzY0MzSlRkV0JjM2FzVVdXTWo1aFVGSGRXWDNIIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjEtMTItMjRUMTM6MjE6MjkuMDg3MjA1KzAxOjAwIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLmhQTTJHTGMxSzlkMkQ4U2J2ZTAwNHg5U3VtakxxYVhUaldoVWh2cVdSd3hmUldsd2ZwNWdIRFVZdVJvRWpoQ1hmTHQtX3Uta25DaFZtSzk4ME4zTEJ3IiwicHJvb2ZQdXJwb3NlIjoiTnV0c1NpZ25pbmdLZXlUeXBlIiwidHlwZSI6Ikpzb25XZWJTaWduYXR1cmUyMDIwIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcjYWJjLW1ldGhvZC0xIn0sInR5cGUiOlsiQ29tcGFueUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfX19.FpeltS-E5f6k65Am0unxCdptvjs1-A-cgOPbYItlhBSZ_Ipx2xBYV6fBBInAvpTITzDYQ6hWVjDfmpmF2B9dUw"
		vp, err := vc.ParseVerifiablePresentation(jwt)
		require.NoError(t, err)
		require.NotNil(t, vp)

		challenge, err := extractChallenge(*vp)

		require.NoError(t, err)
		assert.Equal(t, "nonce", challenge)
	})
}

func assertOAuthError(t *testing.T, err error, expectedDescription string) oauth.OAuth2Error {
	require.Error(t, err)
	oauthErr, ok := err.(oauth.OAuth2Error)
	require.True(t, ok, "expected oauth error")
	assert.Equal(t, oauth.InvalidRequest, oauthErr.Code)
	assert.Equal(t, expectedDescription, oauthErr.Description)
	return oauthErr
}

type stubResponseWriter struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func (s *stubResponseWriter) Header() http.Header {
	if s.headers == nil {
		s.headers = make(http.Header)
	}
	return s.headers

}

func (s *stubResponseWriter) Write(i []byte) (int, error) {
	if s.body == nil {
		s.body = new(bytes.Buffer)
	}
	return s.body.Write(i)
}

func (s *stubResponseWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
}

func putState(ctx *testCtx, session OAuthSession) {
	_ = ctx.client.oauthClientStateStore().Put("state", session)
}

func getState(ctx *testCtx, state string) OAuthSession {
	var session OAuthSession
	_ = ctx.client.oauthClientStateStore().Get(state, &session)
	return session
}

func putNonce(ctx *testCtx, nonce string) {
	_ = ctx.client.oauthNonceStore().Put(nonce, "state")
}

func putCodeSession(ctx *testCtx, code string, oauthSession OAuthSession) {
	_ = ctx.client.oauthCodeStore().Put(code, oauthSession)

}
