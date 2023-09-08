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

package issuer

import (
	"context"
	crypt "crypto"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
	"time"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")
var issuerIdentifier = "https://example.com/" + issuerDID.String()
var holderDID = did.MustParseDID("did:nuts:holder")
var walletIdentifier = "https://example.com/" + holderDID.String()
var keyID = holderDID.String() + "#1"

const definitionsDIR = "./test/valid"

var issuedVC = vc.VerifiableCredential{
	Issuer: issuerDID.URI(),
	CredentialSubject: []interface{}{
		map[string]interface{}{
			"id": holderDID.String(),
		},
	},
	Context: []ssi.URI{
		ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
		ssi.MustParseURI("http://example.org/credentials/V1"),
	},
	Type: []ssi.URI{
		ssi.MustParseURI("VerifiableCredential"),
		ssi.MustParseURI("HumanCredential"),
	},
}

func TestNew(t *testing.T) {
	t.Run("custom definitions", func(t *testing.T) {
		iss, err := NewOpenIDHandler(issuerDID, issuerIdentifier, "./test/valid", nil, nil, storage.NewTestInMemorySessionDatabase(t))

		require.NoError(t, err)
		assert.Len(t, iss.(*openidHandler).credentialsSupported, 3)
	})

	t.Run("error - invalid json", func(t *testing.T) {
		_, err := NewOpenIDHandler(issuerDID, issuerIdentifier, "./test/invalid", nil, nil, storage.NewTestInMemorySessionDatabase(t))

		require.Error(t, err)
		assert.EqualError(t, err, "failed to parse credential definition from test/invalid/invalid.json: unexpected end of JSON input")
	})

	t.Run("error - invalid directory", func(t *testing.T) {
		_, err := NewOpenIDHandler(issuerDID, issuerIdentifier, "./test/non_existing", nil, nil, storage.NewTestInMemorySessionDatabase(t))

		require.Error(t, err)
		assert.EqualError(t, err, "failed to load credential definitions: lstat ./test/non_existing: no such file or directory")
	})
}

func Test_memoryIssuer_Metadata(t *testing.T) {
	t.Run("default definitions", func(t *testing.T) {
		issuer := requireNewTestHandler(t, nil)

		metadata := issuer.Metadata()

		assert.Equal(t, "https://example.com/did:nuts:issuer", metadata.CredentialIssuer)
		assert.Equal(t, "https://example.com/did:nuts:issuer/openid4vci/credential", metadata.CredentialEndpoint)
		require.Len(t, metadata.CredentialsSupported, 3)
		assert.Equal(t, "ldp_vc", metadata.CredentialsSupported[0]["format"])
		require.Len(t, metadata.CredentialsSupported[0]["cryptographic_binding_methods_supported"], 1)
		assert.Equal(t, metadata.CredentialsSupported[0]["credential_definition"],
			map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://www.nuts.nl/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential", "NutsAuthorizationCredential"},
			})
	})
}

func Test_memoryIssuer_ProviderMetadata(t *testing.T) {
	metadata := requireNewTestHandler(t, nil).ProviderMetadata()

	assert.Equal(t, openid4vci.ProviderMetadata{
		Issuer:        "https://example.com/did:nuts:issuer",
		TokenEndpoint: "https://example.com/did:nuts:issuer/token",
		PreAuthorizedGrantAnonymousAccessSupported: true,
	}, metadata)
}

func Test_memoryIssuer_HandleCredentialRequest(t *testing.T) {
	keyStore := crypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	signerKey, _ := keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
		return keyID, nil
	})
	ctrl := gomock.NewController(t)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().ResolveKeyByID(keyID, nil, resolver.NutsSigningKeyType).AnyTimes().Return(signerKey.Public(), nil)

	createHeaders := func() map[string]interface{} {
		return map[string]interface{}{
			"typ": openid4vci.JWTTypeOpenID4VCIProof,
			"kid": keyID,
		}
	}
	createClaims := func(nonce string) map[string]interface{} {
		return map[string]interface{}{
			"aud":   issuerIdentifier,
			"iat":   time.Now().Unix(),
			"nonce": nonce,
		}
	}
	createRequest := func(headers, claims map[string]interface{}) openid4vci.CredentialRequest {
		proof, err := keyStore.SignJWT(ctx, claims, headers, headers["kid"])
		require.NoError(t, err)
		return openid4vci.CredentialRequest{
			Format: openid4vci.VerifiableCredentialJSONLDFormat,
			CredentialDefinition: &openid4vci.CredentialDefinition{
				Context: []ssi.URI{
					ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
					ssi.MustParseURI("http://example.org/credentials/V1"),
				},
				Type: []ssi.URI{
					ssi.MustParseURI("VerifiableCredential"),
					ssi.MustParseURI("HumanCredential"),
				},
			},
			Proof: &openid4vci.CredentialRequestProof{
				Jwt:       proof,
				ProofType: openid4vci.ProofTypeJWT,
			},
		}
	}

	const preAuthCode = "some-secret-code"

	service := requireNewTestHandler(t, keyResolver)
	_, err := service.createOffer(ctx, issuedVC, preAuthCode)
	require.NoError(t, err)
	accessToken, cNonce, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
	require.NoError(t, err)
	validRequest := createRequest(createHeaders(), createClaims(cNonce))

	t.Run("ok", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)
		response, err := service.HandleCredentialRequest(ctx, validRequest, accessToken)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, issuerDID.URI(), response.Issuer)
		auditLogs.AssertContains(t, "VCR", "VerifiableCredentialRetrievedEvent", audit.TestActor, "VC retrieved by wallet over OpenID4VCI")
	})
	t.Run("unsupported format", func(t *testing.T) {
		request := createRequest(createHeaders(), createClaims(cNonce))
		request.Format = "unsupported format"

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		assert.EqualError(t, err, "unsupported_credential_type - credential request: unsupported format 'unsupported format'")
	})
	t.Run("invalid credential_definition", func(t *testing.T) {
		request := createRequest(createHeaders(), createClaims(cNonce))
		request.CredentialDefinition.Type = []ssi.URI{}

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - credential request: invalid credential_definition: missing type field")
	})
	t.Run("proof validation", func(t *testing.T) {
		t.Run("unsupported proof type", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims(""))
			invalidRequest.Proof.ProofType = "not-supported"

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - proof type not supported")
			assert.Nil(t, response)
		})
		t.Run("jwt", func(t *testing.T) {
			t.Run("missing proof", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""))
				invalidRequest.Proof = nil

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - missing proof")
				assert.Nil(t, response)
			})
			t.Run("missing proof returns error with new c_nonce", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""))
				invalidRequest.Proof = nil

				_, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				require.ErrorAs(t, err, new(openid4vci.Error))
				cNonce := err.(openid4vci.Error).CNonce
				assert.NotNil(t, cNonce)
				assert.NotNil(t, err.(openid4vci.Error).CNonceExpiresIn)

				flow, err := service.store.FindByReference(ctx, cNonceRefType, *cNonce)
				require.NoError(t, err)
				assert.NotNil(t, flow)
			})
			t.Run("invalid JWT", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""))
				invalidRequest.Proof.Jwt = "not a JWT"

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid compact serialization format: invalid number of segments")
				assert.Nil(t, response)
			})
			t.Run("not signed by intended wallet (DID differs)", func(t *testing.T) {
				otherIssuedVC := vc.VerifiableCredential{
					Issuer: issuerDID.URI(),
					CredentialSubject: []interface{}{
						map[string]interface{}{
							"id": "did:nuts:other-wallet",
						},
					},
				}

				service := requireNewTestHandler(t, keyResolver)
				_, err := service.createOffer(ctx, otherIssuedVC, preAuthCode)
				require.NoError(t, err)
				accessToken, _, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
				require.NoError(t, err)

				invalidRequest := createRequest(createHeaders(), createClaims(""))

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - credential offer was signed by other DID than intended wallet: did:nuts:holder#1")
				assert.Nil(t, response)
			})
			t.Run("signing key is unknown", func(t *testing.T) {
				keyResolver := resolver.NewMockKeyResolver(ctrl)
				keyResolver.EXPECT().ResolveKeyByID(keyID, nil, resolver.NutsSigningKeyType).AnyTimes().Return(nil, resolver.ErrKeyNotFound)
				service := requireNewTestHandler(t, keyResolver)
				_, err := service.createOffer(ctx, issuedVC, preAuthCode)
				require.NoError(t, err)
				accessToken, _, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
				require.NoError(t, err)

				invalidRequest := createRequest(createHeaders(), createClaims(""))

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - key not found in DID document")
				assert.Nil(t, response)
			})
			t.Run("typ header missing", func(t *testing.T) {
				headers := createHeaders()
				headers["typ"] = ""
				invalidRequest := createRequest(headers, createClaims(""))

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - missing typ header")
				assert.Nil(t, response)
			})
			t.Run("typ header invalid", func(t *testing.T) {
				headers := createHeaders()
				delete(headers, "typ") // causes JWT library to set it to default ("JWT")
				invalidRequest := createRequest(headers, createClaims(""))

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid typ claim (expected: openid4vci-proof+jwt): JWT")
				assert.Nil(t, response)
			})
			t.Run("aud header doesn't match issuer identifier", func(t *testing.T) {
				claims := createClaims("")
				claims["aud"] = "https://example.com/someone-else"
				invalidRequest := createRequest(createHeaders(), claims)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - audience doesn't match credential issuer (aud=[https://example.com/someone-else])")
				assert.Nil(t, response)
			})
		})
		t.Run("unknown nonce", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims("other"))

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - unknown nonce")
			assert.Nil(t, response)
		})
		t.Run("wrong nonce", func(t *testing.T) {
			_, err := service.createOffer(ctx, issuedVC, "other")
			require.NoError(t, err)
			_, cNonce, err := service.HandleAccessTokenRequest(ctx, "other")
			require.NoError(t, err)
			invalidRequest := createRequest(createHeaders(), createClaims(cNonce))

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - nonce not valid for access token")
			assert.Nil(t, response)
		})
		t.Run("request does not match offer", func(t *testing.T) {
			request := createRequest(createHeaders(), createClaims(cNonce))
			request.CredentialDefinition.Type = []ssi.URI{
				ssi.MustParseURI("DifferentCredential"),
			}

			response, err := service.HandleCredentialRequest(ctx, request, accessToken)

			assert.Nil(t, response)
			assert.EqualError(t, err, "invalid_request - requested credential does not match offer: credential does not match credential_definition: type mismatch")
		})
	})

	t.Run("unknown access token", func(t *testing.T) {
		service := requireNewTestHandler(t, keyResolver)

		response, err := service.HandleCredentialRequest(ctx, validRequest, accessToken)

		assertProtocolError(t, err, http.StatusBadRequest, "invalid_token - unknown access token")
		assert.Nil(t, response)
	})
}

func Test_memoryIssuer_OfferCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := openid4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(nil)
		service := requireNewTestHandler(t, nil)
		service.walletClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.WalletAPIClient, error) {
			return wallet, nil
		}

		err := service.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.NoError(t, err)
	})
	t.Run("client offer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := openid4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().Metadata().Return(openid4vci.OAuth2ClientMetadata{CredentialOfferEndpoint: "here-please"})
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(errors.New("failed"))
		service := requireNewTestHandler(t, nil)
		service.walletClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.WalletAPIClient, error) {
			return wallet, nil
		}

		err := service.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.EqualError(t, err, "unable to offer credential (client-metadata-url=here-please): failed")
	})
}

func Test_memoryIssuer_HandleAccessTokenRequest(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		service := requireNewTestHandler(t, nil)
		_, err := service.createOffer(ctx, issuedVC, "code")
		require.NoError(t, err)

		accessToken, _, err := service.HandleAccessTokenRequest(audit.TestContext(), "code")

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})
	t.Run("pre-authorized code issued by other issuer", func(t *testing.T) {
		store := storage.NewTestInMemorySessionDatabase(t)
		service, err := NewOpenIDHandler(issuerDID, issuerIdentifier, definitionsDIR, &http.Client{}, nil, store)
		require.NoError(t, err)
		_, err = service.(*openidHandler).createOffer(ctx, issuedVC, "code")
		require.NoError(t, err)

		otherService, err := NewOpenIDHandler(did.MustParseDID("did:nuts:other"), "http://example.com/other", definitionsDIR, &http.Client{}, nil, store)
		require.NoError(t, err)
		accessToken, _, err := otherService.HandleAccessTokenRequest(audit.TestContext(), "code")

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_grant - pre-authorized code not issued by this issuer")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		assert.Empty(t, accessToken)
	})
	t.Run("unknown pre-authorized code", func(t *testing.T) {
		service := requireNewTestHandler(t, nil)
		_, err := service.createOffer(ctx, issuedVC, "some-other-code")
		require.NoError(t, err)

		accessToken, _, err := service.HandleAccessTokenRequest(audit.TestContext(), "code")

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_grant - unknown pre-authorized code")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		assert.Empty(t, accessToken)
	})
}

func assertProtocolError(t *testing.T, err error, statusCode int, message string) {
	var protocolError openid4vci.Error
	require.ErrorAs(t, err, &protocolError)
	assert.EqualError(t, protocolError, message)
	assert.Equal(t, statusCode, protocolError.StatusCode)
}

func requireNewTestHandler(t *testing.T, keyResolver resolver.KeyResolver) *openidHandler {
	service, err := NewOpenIDHandler(issuerDID, issuerIdentifier, definitionsDIR, &http.Client{}, keyResolver, storage.NewTestInMemorySessionDatabase(t))
	require.NoError(t, err)
	return service.(*openidHandler)
}
