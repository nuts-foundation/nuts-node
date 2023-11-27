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
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/url"
)

func TestWrapper_RequestAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	verifierDID := did.MustParseDID("did:test:456")
	body := &RequestAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second"}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(verifierDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
		ctx.relyingParty.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second").Return(&oauth.TokenResponse{}, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.NoError(t, err)
	})
	t.Run("error - DID not owned", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(false, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.ErrorContains(t, err, "not owned by this node")
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: "invalid", Body: body})

		require.EqualError(t, err, "did not found: invalid DID")
	})
	t.Run("error - missing request body", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String()})

		require.Error(t, err)
		assert.EqualError(t, err, "missing request body")
	})
	t.Run("error - invalid verifier did", func(t *testing.T) {
		ctx := newTestClient(t)
		body := &RequestAccessTokenJSONRequestBody{Verifier: "invalid"}
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "invalid verifier: invalid DID")
	})
	t.Run("error - verifier not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(verifierDID, nil).Return(nil, nil, resolver.ErrNotFound)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "verifier not found: unable to find the DID document")
	})
	t.Run("error - verifier error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(verifierDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
		ctx.relyingParty.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second").Return(nil, core.Error(http.StatusPreconditionFailed, "no matching credentials"))

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "no matching credentials")
	})
}

func TestWrapper_handleS2SAccessTokenRequest(t *testing.T) {
	issuerDID := did.MustParseDID("did:test:123")
	const requestedScope = "eOverdracht-overdrachtsbericht"
	// Create issuer DID document and keys
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerDIDDocument := did.Document{
		ID: issuerDID,
	}
	keyID := did.DIDURL{DID: issuerDID}
	keyID.Fragment = "1"
	verificationMethod, err := did.NewVerificationMethod(keyID, ssi.JsonWebKey2020, issuerDID, keyPair.Public())
	require.NoError(t, err)
	issuerDIDDocument.AddAssertionMethod(verificationMethod)

	var submission pe.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(`
{
  "descriptor_map": [
    {
      "id": "1",
      "path": "$.verifiableCredential",
      "format": "ldp_vc"
    }
  ]
}`), &submission))
	submissionJSON, _ := json.Marshal(submission)
	verifiableCredential := credential.ValidNutsOrganizationCredential(t)
	subjectDID, _ := verifiableCredential.SubjectDID()
	presentation := test.CreateJSONLDPresentation(t, *subjectDID, verifiableCredential)

	t.Run("JSON-LD VP", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.verifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		require.NoError(t, err)
		require.IsType(t, HandleTokenRequest200JSONResponse{}, resp)
		tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
		assert.Equal(t, "bearer", tokenResponse.TokenType)
		assert.Equal(t, requestedScope, *tokenResponse.Scope)
		assert.Equal(t, int(accessTokenValidity.Seconds()), *tokenResponse.ExpiresIn)
		assert.NotEmpty(t, tokenResponse.AccessToken)
	})
	t.Run("missing parameters", func(t *testing.T) {
		ctx := newTestClient(t)
		params := map[string]string{
			"scope": requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, "invalid_request - missing required parameters")
		assert.Nil(t, resp)
	})
	t.Run("missing presentation expiry date", func(t *testing.T) {
		ctx := newTestClient(t)
		presentation := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
			require.NoError(t, token.Remove(jwt.ExpirationKey))
		}, verifiableCredential)

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		_, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		require.EqualError(t, err, "invalid_request - presentation is missing creation or expiration date")
	})
	t.Run("missing presentation not before date", func(t *testing.T) {
		ctx := newTestClient(t)
		presentation := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
			require.NoError(t, token.Remove(jwt.NotBeforeKey))
		}, verifiableCredential)

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		_, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		require.EqualError(t, err, "invalid_request - presentation is missing creation or expiration date")
	})
	t.Run("missing presentation valid for too long", func(t *testing.T) {
		ctx := newTestClient(t)
		presentation := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
			require.NoError(t, token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
		}, verifiableCredential)

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		_, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		require.EqualError(t, err, "invalid_request - presentation is valid for too long (max 10s)")
	})
	t.Run("JWT VP", func(t *testing.T) {
		ctx := newTestClient(t)
		presentation := test.CreateJWTPresentation(t, *subjectDID, nil, verifiableCredential)
		ctx.verifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		require.NoError(t, err)
		require.IsType(t, HandleTokenRequest200JSONResponse{}, resp)
		tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
		assert.Equal(t, "bearer", tokenResponse.TokenType)
		assert.Equal(t, requestedScope, *tokenResponse.Scope)
		assert.Equal(t, int(accessTokenValidity.Seconds()), *tokenResponse.ExpiresIn)
		assert.NotEmpty(t, tokenResponse.AccessToken)
	})
	t.Run("replay attack (nonce is reused)", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.verifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		_, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)
		require.NoError(t, err)

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)
		assert.EqualError(t, err, "invalid_request - presentation nonce has already been used")
		assert.Nil(t, resp)
	})
	t.Run("VP is not valid JSON", func(t *testing.T) {
		ctx := newTestClient(t)
		params := map[string]string{
			"assertion":               url.QueryEscape("[true, false]"),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, "invalid_request - assertion parameter is invalid: unable to parse PEX envelope as list of verifiable presentations: invalid JWT")
		assert.Nil(t, resp)
	})
	t.Run("VP verification fails", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.verifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(nil, errors.New("invalid"))

		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, "invalid_request - invalid - presentation(s) or contained credential(s) are invalid")
		assert.Nil(t, resp)
	})
	t.Run("proof of ownership", func(t *testing.T) {
		t.Run("VC without credentialSubject.id", func(t *testing.T) {
			ctx := newTestClient(t)
			verifiablePresentation := test.CreateJSONLDPresentation(t, *subjectDID, vc.VerifiableCredential{
				CredentialSubject: []interface{}{map[string]string{}},
			})
			verifiablePresentationJSON, _ := verifiablePresentation.MarshalJSON()
			params := map[string]string{
				"assertion":               url.QueryEscape(string(verifiablePresentationJSON)),
				"presentation_submission": url.QueryEscape(string(submissionJSON)),
				"scope":                   requestedScope,
			}

			resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

			assert.EqualError(t, err, `invalid_request - unable to get subject DID from VC: credential subjects have no ID`)
			assert.Nil(t, resp)
		})
		t.Run("signing key is not owned by credentialSubject.id", func(t *testing.T) {
			ctx := newTestClient(t)
			invalidProof := presentation.Proof[0].(map[string]interface{})
			invalidProof["verificationMethod"] = "did:example:other#1"
			verifiablePresentation := vc.VerifiablePresentation{
				VerifiableCredential: []vc.VerifiableCredential{verifiableCredential},
				Proof:                []interface{}{invalidProof},
			}
			verifiablePresentationJSON, _ := verifiablePresentation.MarshalJSON()
			params := map[string]string{
				"assertion":               url.QueryEscape(string(verifiablePresentationJSON)),
				"presentation_submission": url.QueryEscape(string(submissionJSON)),
				"scope":                   requestedScope,
			}

			resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

			assert.EqualError(t, err, `invalid_request - presentation signer is not credential subject`)
			assert.Nil(t, resp)
		})
	})
	t.Run("submission is not valid JSON", func(t *testing.T) {
		ctx := newTestClient(t)
		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape("not-a-valid-submission"),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, `invalid_request - invalid presentation submission: invalid character 'o' in literal null (expecting 'u')`)
		assert.Nil(t, resp)
	})
	t.Run("unsupported scope", func(t *testing.T) {
		ctx := newTestClient(t)
		params := map[string]string{
			"assertion":               url.QueryEscape(presentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   "everything",
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, `invalid_scope - unsupported scope for presentation exchange: everything`)
		assert.Nil(t, resp)
	})
	t.Run("re-evaluation of presentation definition yields different credentials", func(t *testing.T) {
		// This indicates the client presented credentials that don't actually match the presentation definition,
		// which could indicate a malicious client.
		otherVerifiableCredential := vc.VerifiableCredential{
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": subjectDID.String(),
					// just for demonstration purposes, what matters is that the credential does not match the presentation definition.
					"IsAdministrator": true,
				},
			},
		}
		verifiablePresentation := test.CreateJSONLDPresentation(t, *subjectDID, otherVerifiableCredential)

		ctx := newTestClient(t)

		params := map[string]string{
			"assertion":               url.QueryEscape(verifiablePresentation.Raw()),
			"presentation_submission": url.QueryEscape(string(submissionJSON)),
			"scope":                   requestedScope,
		}

		resp, err := ctx.client.handleS2SAccessTokenRequest(issuerDID, params)

		assert.EqualError(t, err, "invalid_request - presentation submission doesn't match presentation definition - presentation submission does not conform to Presentation Definition")
		assert.Nil(t, resp)
	})
}

func TestWrapper_createAccessToken(t *testing.T) {
	credential, err := vc.ParseVerifiableCredential(jsonld.TestOrganizationCredential)
	require.NoError(t, err)
	presentation := vc.VerifiablePresentation{
		VerifiableCredential: []vc.VerifiableCredential{*credential},
	}
	submission := pe.PresentationSubmission{
		Id: "submissive",
	}
	definition := pe.PresentationDefinition{
		Id: "definitive",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		accessToken, err := ctx.client.createAccessToken(issuerDID, time.Now(), []VerifiablePresentation{presentation}, submission, definition, "everything")

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken.AccessToken)
		assert.Equal(t, "bearer", accessToken.TokenType)
		assert.Equal(t, 900, *accessToken.ExpiresIn)
		assert.Equal(t, "everything", *accessToken.Scope)

		var storedToken AccessToken
		err = ctx.client.s2sAccessTokenStore().Get(accessToken.AccessToken, &storedToken)
		require.NoError(t, err)
		assert.Equal(t, accessToken.AccessToken, storedToken.Token)
		assert.Equal(t, submission, *storedToken.PresentationSubmission)
		assert.Equal(t, definition, *storedToken.PresentationDefinition)
		expectedVPJSON, _ := presentation.MarshalJSON()
		actualVPJSON, _ := storedToken.VPToken[0].MarshalJSON()
		assert.JSONEq(t, string(expectedVPJSON), string(actualVPJSON))
		assert.Equal(t, issuerDID.String(), storedToken.Issuer)
		assert.NotEmpty(t, storedToken.Expiration)
	})
}
