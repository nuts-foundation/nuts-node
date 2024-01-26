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
	"net/http"
	"net/url"
	"strings"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	oauth2 "github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var holderDID = did.MustParseDID("did:web:example.com:iam:holder")
var issuerDID = did.MustParseDID("did:web:example.com:iam:issuer")

func TestWrapper_handleAuthorizeRequestFromHolder(t *testing.T) {
	defaultParams := func() map[string]string {
		return map[string]string{
			oauth.ClientIDParam:    holderDID.String(),
			oauth.RedirectURIParam: "https://example.com",
			responseTypeParam:      "code",
			oauth.ScopeParam:       "test",
		}
	}

	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[oauth.ClientIDParam] = "did:nuts:1"

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)")
	})
	t.Run("missing did in supported_client_id_schemes", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		ctx.verifierRole.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:    "http://example.com",
			ClientIdSchemesSupported: []string{"not_did"},
		}, nil)
		ctx.verifierRole.EXPECT().ClientMetadataURL(verifierDID).Return(test.MustParseURL("https://example.com/.well-known/authorization-server/iam/verifier"), nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "wallet metadata does not contain did in client_id_schemes_supported")
	})
	t.Run("error on authorization server metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.verifierRole.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(nil, assert.AnError)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.ServerError, "failed to get metadata from wallet")
	})
	t.Run("failed to generate verifier web url", func(t *testing.T) {
		ctx := newTestClient(t)
		verifierDID := did.MustParseDID("did:notweb:example.com:verifier")
		ctx.verifierRole.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{}, nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.ServerError, "invalid verifier DID")
	})
	t.Run("incorrect holder AuthorizationEndpoint URL", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.verifierRole.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint: "://example.com",
		}, nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid wallet endpoint")
	})
}

func TestWrapper_handleAuthorizeRequestFromVerifier(t *testing.T) {
	responseURI := "https://example.com/iam/verifier/response"
	clientMetadata := oauth.OAuthClientMetadata{
		VPFormats: oauth.DefaultOpenIDSupportedFormats(),
	}
	defaultParams := func() map[string]string {
		return map[string]string{
			oauth.ClientIDParam:     verifierDID.String(),
			clientIDSchemeParam:     didScheme,
			clientMetadataURIParam:  "https://example.com/.well-known/authorization-server/iam/verifier",
			nonceParam:              "nonce",
			presentationDefUriParam: "https://example.com/iam/verifier/presentation_definition?scope=test",
			responseModeParam:       responseModeDirectPost,
			responseURIParam:        responseURI,
			responseTypeParam:       responseTypeVPToken,
			oauth.ScopeParam:        "test",
			oauth.StateParam:        "state",
		}
	}

	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[oauth.ClientIDParam] = "did:nuts:1"
		expectPostError(t, ctx, oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("invalid client_id_scheme", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[clientIDSchemeParam] = "other"
		expectPostError(t, ctx, oauth.InvalidRequest, "invalid client_id_scheme parameter", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("missing client_metadata_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, clientMetadataURIParam)
		ctx.holderRole.EXPECT().ClientMetadata(gomock.Any(), "").Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, "failed to get client metadata (verifier)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("missing nonce", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, nonceParam)
		expectPostError(t, ctx, oauth.InvalidRequest, "missing nonce parameter", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("invalid presentation_definition_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[presentationDefUriParam] = "://example.com"
		ctx.holderRole.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, "failed to get client metadata (verifier)", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("missing response_mode", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseModeParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		assert.EqualError(t, err, "invalid_request - invalid response_mode parameter")
	})
	t.Run("missing response_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseURIParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		assert.EqualError(t, err, "invalid_request - missing response_uri parameter")
	})
	t.Run("missing state and missing response_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, responseURIParam)

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.Error(t, err)
	})
	t.Run("invalid presentation_definition_uri", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, "state")
		ctx.holderRole.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.holderRole.EXPECT().PresentationDefinition(gomock.Any(), "https://example.com/iam/verifier/presentation_definition?scope=test").Return(nil, assert.AnError)
		expectPostError(t, ctx, oauth.InvalidPresentationDefinitionURI, "failed to retrieve presentation definition on https://example.com/iam/verifier/presentation_definition?scope=test", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("failed to create verifiable presentation", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, "state")
		ctx.holderRole.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.holderRole.EXPECT().PresentationDefinition(gomock.Any(), "https://example.com/iam/verifier/presentation_definition?scope=test").Return(&pe.PresentationDefinition{}, nil)
		ctx.holderRole.EXPECT().BuildPresentation(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, "nonce", verifierDID.URI()).Return(nil, nil, assert.AnError)
		expectPostError(t, ctx, oauth.ServerError, assert.AnError.Error(), responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
	t.Run("missing credentials in wallet", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		putState(ctx, "state")
		ctx.holderRole.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.holderRole.EXPECT().PresentationDefinition(gomock.Any(), "https://example.com/iam/verifier/presentation_definition?scope=test").Return(&pe.PresentationDefinition{}, nil)
		ctx.holderRole.EXPECT().BuildPresentation(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, "nonce", verifierDID.URI()).Return(nil, nil, oauth2.ErrNoCredentials)
		expectPostError(t, ctx, oauth.InvalidRequest, "no credentials available", responseURI, "state")

		_, err := ctx.client.handleAuthorizeRequestFromVerifier(context.Background(), holderDID, params)

		require.NoError(t, err)
	})
}

func TestWrapper_HandleAuthorizeResponse(t *testing.T) {
	t.Run("submission", func(t *testing.T) {
		challenge := "challenge"
		// simple vp
		vpToken := `{"type":"VerifiablePresentation", "verifiableCredential":{"type":"VerifiableCredential", "credentialSubject":{"id":"did:web:example.com:iam:holder"}},"proof":{"challenge":"challenge","domain":"did:web:example.com:iam:verifier","proofPurpose":"assertionMethod","type":"JsonWebSignature2020","verificationMethod":"did:web:example.com:iam:holder#0"}}`
		// simple definition
		definition := pe.PresentationDefinition{InputDescriptors: []*pe.InputDescriptor{
			{Id: "1", Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}},
		}}
		// simple submission
		submissionAsStr := `{"id":"1", "definition_id":"1", "descriptor_map":[{"id":"1","format":"ldp_vc","path":"$.verifiableCredential"}]}`
		// simple request
		baseRequest := func() HandleAuthorizeResponseRequestObject {
			return HandleAuthorizeResponseRequestObject{
				Body: &HandleAuthorizeResponseFormdataRequestBody{
					VpToken:                &vpToken,
					PresentationSubmission: &submissionAsStr,
				},
				Id: "verifier",
			}
		}
		t.Run("ok", func(t *testing.T) {
			ctx := newTestClient(t)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinition(gomock.Any(), gomock.Any(), "test").Return(&definition, nil)
			ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Return(nil, nil)

			response, err := ctx.client.HandleAuthorizeResponse(context.Background(), baseRequest())

			require.NoError(t, err)
			redirectURI := response.(HandleAuthorizeResponse200JSONResponse).RedirectURI
			assert.Contains(t, redirectURI, "https://example.com/iam/holder/cb?code=")
			assert.Contains(t, redirectURI, "state=state")
		})
		t.Run("failed to verify vp", func(t *testing.T) {
			ctx := newTestClient(t)
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinition(gomock.Any(), gomock.Any(), "test").Return(&definition, nil)
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
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "invalid presentation_submission: invalid character '}' looking for beginning of value")
		})
		t.Run("missing presentation_submission", func(t *testing.T) {
			ctx := newTestClient(t)
			request := baseRequest()
			request.Body.PresentationSubmission = nil
			putNonce(ctx, challenge)
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

			_, err := ctx.client.HandleAuthorizeResponse(context.Background(), request)

			_ = assertOAuthError(t, err, "missing presentation_submission")
		})
		t.Run("invalid signer", func(t *testing.T) {
			ctx := newTestClient(t)
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
			putNonce(ctx, challenge)
			request := baseRequest()
			submission := `{"id":"1", "definition_id":"2", "descriptor_map":[{"id":"2","format":"ldp_vc","path":"$.verifiableCredential"}]}`
			request.Body.PresentationSubmission = &submission
			ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
			ctx.policy.EXPECT().PresentationDefinition(gomock.Any(), gomock.Any(), "test").Return(&definition, nil)

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
				Id: "verifier",
			}
		}
		t.Run("with client state", func(t *testing.T) {
			ctx := newTestClient(t)
			putState(ctx, "state")

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
	definition := pe.PresentationDefinition{InputDescriptors: []*pe.InputDescriptor{
		{Id: "1", Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}},
	}}
	submissionAsStr := `{"id":"1", "definition_id":"1", "descriptor_map":[{"id":"1","format":"ldp_vc","path":"$.verifiableCredential"}]}`
	var submission pe.PresentationSubmission
	_ = json.Unmarshal([]byte(submissionAsStr), &submission)
	validSession := OAuthSession{
		ClientID:    clientID,
		OwnDID:      &verifierDID,
		RedirectURI: redirectURI,
		Scope:       "scope",
		ServerState: map[string]interface{}{
			"presentations":          []vc.VerifiablePresentation{*vp},
			"presentationSubmission": submission,
		},
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		putSession(ctx, code, validSession)
		ctx.policy.EXPECT().PresentationDefinition(gomock.Any(), verifierDID, "scope").Return(&definition, nil)

		response, err := ctx.client.handleAccessTokenRequest(context.Background(), verifierDID, &code, &redirectURI, &clientID)

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

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), verifierDID, &code, &redirectURI, &clientID)

		require.Error(t, err)
		_ = assertOAuthError(t, err, "invalid authorization code")
	})
	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		putSession(ctx, code, validSession)
		clientID := "other"

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), verifierDID, &code, &redirectURI, &clientID)

		require.Error(t, err)
		_ = assertOAuthError(t, err, "client_id does not match: did:web:example.com:iam:holder vs other")
	})
	t.Run("invalid redirectURI", func(t *testing.T) {
		ctx := newTestClient(t)
		putSession(ctx, code, validSession)
		redirectURI := "other"

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), verifierDID, &code, &redirectURI, &clientID)

		require.Error(t, err)
		_ = assertOAuthError(t, err, "redirect_uri does not match: https://example.com/iam/holder/cb vs other")
	})
	t.Run("presentation definition backend server error", func(t *testing.T) {
		ctx := newTestClient(t)
		putSession(ctx, code, validSession)
		ctx.policy.EXPECT().PresentationDefinition(gomock.Any(), verifierDID, "scope").Return(nil, assert.AnError)

		_, err := ctx.client.handleAccessTokenRequest(context.Background(), verifierDID, &code, &redirectURI, &clientID)

		require.Error(t, err)
		oauthErr, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.ServerError, oauthErr.Code)
		assert.Equal(t, "failed to fetch presentation definition: assert.AnError general error for testing", oauthErr.Description)
	})
}

func Test_handleCallback(t *testing.T) {
	code := "code"
	state := "state"

	t.Run("err - missing state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Id: webIDPart,
			Params: CallbackParams{
				Code: &code,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing state parameter")
	})
	t.Run("err - expired state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Id: webIDPart,
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid or expired state")
	})
	t.Run("err - missing code", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, state)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Id: webIDPart,
			Params: CallbackParams{
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing code parameter")
	})
	t.Run("err - failed to retrieve access token", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, state)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		ctx.relyingParty.EXPECT().AccessToken(gomock.Any(), code, verifierDID, "https://example.com/iam/123/callback", holderDID).Return(nil, assert.AnError)

		_, err := ctx.client.handleCallback(nil, CallbackRequestObject{
			Id: webIDPart,
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

// expectPostError is a convenience method to add an expectation to the holderRole mock.
// it checks if the right error is posted to the verifier.
func expectPostError(t *testing.T, ctx *testCtx, errorCode oauth.ErrorCode, description string, expectedResponseURI string, verifierClientState string) {
	ctx.holderRole.EXPECT().PostError(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, err oauth.OAuth2Error, responseURI string, state string) (string, error) {
		assert.Equal(t, errorCode, err.Code)
		assert.Equal(t, description, err.Description)
		assert.Equal(t, expectedResponseURI, responseURI)
		assert.Equal(t, verifierClientState, state)
		holderURL, _ := didweb.DIDToURL(holderDID)
		require.NotNil(t, holderURL)
		return holderURL.JoinPath("callback").String(), nil
	})
}

func TestWrapper_sendAndHandleDirectPost(t *testing.T) {
	t.Run("failed to post response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.holderRole.EXPECT().PostAuthorizationResponse(gomock.Any(), gomock.Any(), gomock.Any(), "response", "").Return("", assert.AnError)

		_, err := ctx.client.sendAndHandleDirectPost(context.Background(), vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "response", "")

		assert.Equal(t, assert.AnError, err)
	})
}

func TestWrapper_sendAndHandleDirectPostError(t *testing.T) {
	t.Run("failed to post error with redirect available", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.holderRole.EXPECT().PostError(gomock.Any(), gomock.Any(), "response", "state").Return("", assert.AnError)
		redirectURI := test.MustParseURL("https://example.com/redirect")
		expected := HandleAuthorizeRequest302Response{
			Headers: HandleAuthorizeRequest302ResponseHeaders{
				Location: "https://example.com/redirect?error=server_error&error_description=failed+to+post+error+to+verifier+%40+response",
			},
		}

		redirect, err := ctx.client.sendAndHandleDirectPostError(context.Background(), oauth.OAuth2Error{RedirectURI: redirectURI}, holderDID, "response", "state")

		require.NoError(t, err)
		assert.Equal(t, expected, redirect)
	})
	t.Run("failed to post error without redirect available", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.holderRole.EXPECT().PostError(gomock.Any(), gomock.Any(), "response", "state").Return("", assert.AnError)

		_, err := ctx.client.sendAndHandleDirectPostError(context.Background(), oauth.OAuth2Error{}, holderDID, "response", "state")

		require.Error(t, err)
		require.Equal(t, "server_error - something went wrong", err.Error())
	})
}

func TestWrapper_sendPresentationRequest(t *testing.T) {
	instance := New(nil, nil, nil, nil, nil)

	redirectURI, _ := url.Parse("https://example.com/redirect")
	verifierID, _ := url.Parse("https://example.com/verifier")
	walletID, _ := url.Parse("https://example.com/wallet")

	httpResponse := &stubResponseWriter{}

	err := instance.sendPresentationRequest(context.Background(), httpResponse, "test-scope", *redirectURI, *verifierID, *walletID)

	require.NoError(t, err)
	require.Equal(t, http.StatusFound, httpResponse.statusCode)
	location := httpResponse.headers.Get("Location")
	require.NotEmpty(t, location)
	locationURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "https", locationURL.Scheme)
	assert.Equal(t, "example.com", locationURL.Host)
	assert.Equal(t, "/wallet/authorize", locationURL.Path)
	assert.Equal(t, "test-scope", locationURL.Query().Get("scope"))
	assert.Equal(t, "vp_token id_token", locationURL.Query().Get("response_type"))
	assert.Equal(t, "direct_post", locationURL.Query().Get("response_mode"))
	assert.Equal(t, "https://example.com/verifier/.well-known/openid-wallet-metadata/metadata.xml", locationURL.Query().Get("client_metadata_uri"))
}

func TestWrapper_handlePresentationRequest(t *testing.T) {
	credentialID, _ := ssi.ParseURI("did:web:example.com:issuer#6AF53584-3337-4766-8C8D-0BFD54F6E527")
	walletCredentials := []vc.VerifiableCredential{
		{
			Context: []ssi.URI{
				vc.VCContextV1URI(),
				credential.NutsV1ContextURI,
			},
			ID:     credentialID,
			Issuer: issuerDID.URI(),
			Type:   []ssi.URI{vc.VerifiableCredentialTypeV1URI(), *credential.NutsOrganizationCredentialTypeURI},
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": holderDID.URI(),
					"organization": map[string]interface{}{
						"name": "Test Organization",
						"city": "Test City",
					},
				},
			},
		},
	}
	t.Run("with scope", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockVDR := vdr.NewMockVDR(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockWallet := holder.NewMockWallet(ctrl)
		mockPolicy := policy.NewMockPDPBackend(ctrl)
		mockVCR.EXPECT().Wallet().Return(mockWallet)
		mockAuth := auth.NewMockAuthenticationServices(ctrl)
		mockWallet.EXPECT().List(gomock.Any(), holderDID).Return(walletCredentials, nil)
		mockVDR.EXPECT().IsOwner(gomock.Any(), holderDID).Return(true, nil)
		instance := New(mockAuth, mockVCR, mockVDR, storage.NewTestStorageEngine(t), mockPolicy)

		params := map[string]string{
			"scope":                   "eOverdracht-overdrachtsbericht",
			"response_type":           "code",
			"response_mode":           "direct_post",
			"client_metadata_uri":     "https://example.com/client_metadata.xml",
			"presentation_definition": `{"id":"1","input_descriptors":[]}`,
		}

		response, err := instance.handlePresentationRequest(context.Background(), params, createSession(params, holderDID))

		require.NoError(t, err)
		httpResponse := &stubResponseWriter{}
		_ = response.VisitHandleAuthorizeRequestResponse(httpResponse)
		require.Equal(t, http.StatusOK, httpResponse.statusCode)
		assert.Contains(t, httpResponse.body.String(), "</html>")
	})
	t.Run("invalid response_mode", func(t *testing.T) {
		instance := New(nil, nil, nil, nil, nil)
		params := map[string]string{
			"scope":                   "eOverdracht-overdrachtsbericht",
			"response_type":           "code",
			"response_mode":           "invalid",
			"client_metadata_uri":     "https://example.com/client_metadata.xml",
			"presentation_definition": "{}",
		}

		response, err := instance.handlePresentationRequest(context.Background(), params, createSession(params, holderDID))

		requireOAuthError(t, err, oauth.InvalidRequest, "response_mode must be direct_post")
		assert.Nil(t, response)
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

func putState(ctx *testCtx, state string) {
	_ = ctx.client.oauthClientStateStore().Put(state, OAuthSession{
		SessionID:   "token",
		OwnDID:      &holderDID,
		RedirectURI: "https://example.com/iam/holder/cb",
		VerifierDID: &verifierDID,
	})
}

func putNonce(ctx *testCtx, nonce string) {
	_ = ctx.client.oauthNonceStore().Put(nonce, OAuthSession{Scope: "test", ClientState: "state", OwnDID: &verifierDID, RedirectURI: "https://example.com/iam/holder/cb"})
}

func putSession(ctx *testCtx, code string, oauthSession OAuthSession) {
	_ = ctx.client.oauthCodeStore().Put(code, oauthSession)
}
