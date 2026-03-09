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
	"os"
	"path/filepath"
	"testing"
	"time"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")
var issuerIdentifier = "https://example.com/" + issuerDID.String()
var holderDID = did.MustParseDID("did:nuts:holder")
var keyID = holderDID.String() + "#1"

const definitionsDIR = "./test/valid"

var issuedVC = vc.VerifiableCredential{
	Issuer: issuerDID.URI(),
	CredentialSubject: []map[string]any{
		{
			"id": holderDID.String(),
		},
	},
	Context: []ssi.URI{
		ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
		ssi.MustParseURI("https://example.com/credentials/v1"),
	},
	Type: []ssi.URI{
		ssi.MustParseURI("VerifiableCredential"),
		ssi.MustParseURI("ExampleCredential"),
	},
}

func TestNew(t *testing.T) {
	t.Run("custom definitions", func(t *testing.T) {
		iss, err := NewOpenIDHandler(issuerDID, issuerIdentifier, "./test/valid", nil, nil, storage.NewTestInMemorySessionDatabase(t))

		require.NoError(t, err)
		assert.Len(t, iss.(*openidHandler).credentialConfigurationsSupported, 3)
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
		assert.Equal(t, "https://example.com/did:nuts:issuer/openid4vci/nonce", metadata.NonceEndpoint)
		require.Len(t, metadata.CredentialConfigurationsSupported, 3)
		// Assert all 3 config IDs by name
		for _, expectedID := range []string{
			"NutsAuthorizationCredential_ldp_vc",
			"NutsOrganizationCredential_ldp_vc",
			"ExampleCredential_ldp_vc",
		} {
			_, ok := metadata.CredentialConfigurationsSupported[expectedID]
			assert.True(t, ok, "expected config ID %s to be present", expectedID)
		}
		// Spot-check NutsAuthorizationCredential details
		authCredConfig := metadata.CredentialConfigurationsSupported["NutsAuthorizationCredential_ldp_vc"]
		assert.Equal(t, "ldp_vc", authCredConfig["format"])
		require.Len(t, authCredConfig["cryptographic_binding_methods_supported"], 1)
		assert.Equal(t, authCredConfig["credential_definition"],
			map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential", "NutsAuthorizationCredential"},
			})
	})
	t.Run("duplicate credential_configuration_id from external dir is rejected", func(t *testing.T) {
		// Create a temp dir with a definition that duplicates a built-in config ID
		tmpDir := t.TempDir()
		duplicateDef := `{
			"format": "ldp_vc",
			"cryptographic_binding_methods_supported": ["did:nuts"],
			"credential_definition": {
				"@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
				"type": ["VerifiableCredential", "NutsOrganizationCredential"]
			}
		}`
		err := os.WriteFile(filepath.Join(tmpDir, "duplicate.json"), []byte(duplicateDef), 0644)
		require.NoError(t, err)

		_, err = NewOpenIDHandler(issuerDID, issuerIdentifier, tmpDir, &http.Client{}, nil, storage.NewTestInMemorySessionDatabase(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate credential_configuration_id 'NutsOrganizationCredential_ldp_vc'")
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
	keyStore := crypto.NewMemoryCryptoInstance(t)
	ctx := audit.TestContext()
	_, signerKey, _ := keyStore.New(ctx, crypto.StringNamingFunc(keyID))
	ctrl := gomock.NewController(t)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().ResolveKeyByID(keyID, nil, resolver.NutsSigningKeyType).AnyTimes().Return(signerKey, nil)

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
	createProofs := func(headers, claims map[string]interface{}) *openid4vci.CredentialRequestProofs {
		proof, err := keyStore.SignJWT(ctx, claims, headers, headers["kid"].(string))
		require.NoError(t, err)
		return &openid4vci.CredentialRequestProofs{
			Jwt: []string{proof},
		}
	}
	createRequest := func(headers, claims map[string]interface{}, configID string) openid4vci.CredentialRequest {
		return openid4vci.CredentialRequest{
			CredentialConfigurationId: configID,
			Proofs:                    createProofs(headers, claims),
		}
	}

	const preAuthCode = "some-secret-code"

	service := requireNewTestHandler(t, keyResolver)
	offer, err := service.createOffer(ctx, issuedVC, preAuthCode)
	require.NoError(t, err)
	accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
	require.NoError(t, err)
	nonce, err := service.HandleNonceRequest(ctx)
	require.NoError(t, err)
	configID := offer.CredentialConfigurationIds[0]
	validRequest := createRequest(createHeaders(), createClaims(nonce), configID)

	t.Run("ok", func(t *testing.T) {
		auditLogs := audit.CaptureAuditLogs(t)
		response, err := service.HandleCredentialRequest(ctx, validRequest, accessToken)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, issuerDID.URI(), response.Issuer)
		auditLogs.AssertContains(t, "VCR", "VerifiableCredentialRetrievedEvent", audit.TestActor, "VC retrieved by wallet over OpenID4VCI")
	})
	t.Run("error - missing credential_configuration_id", func(t *testing.T) {
		request := openid4vci.CredentialRequest{
			Proofs: createProofs(createHeaders(), createClaims(nonce)),
		}

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_credential_request - credential request must contain credential_configuration_id")
	})
	t.Run("error - unknown credential_configuration_id", func(t *testing.T) {
		request := createRequest(createHeaders(), createClaims(nonce), "NonExistent_ldp_vc")

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		require.ErrorAs(t, err, new(openid4vci.Error))
		assert.Equal(t, openid4vci.UnknownCredentialConfiguration, err.(openid4vci.Error).Code)
	})
	t.Run("proof validation", func(t *testing.T) {
		t.Run("missing proofs", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
			invalidRequest.Proofs = nil

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - missing proofs")
			assert.Nil(t, response)
		})
		t.Run("jwt", func(t *testing.T) {
			t.Run("invalid JWT", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
				invalidRequest.Proofs.Jwt = []string{"not a JWT"}

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid JWT typ header (expected 'openid4vci-proof+jwt', got '')")
				assert.Nil(t, response)
			})
			t.Run("not signed by intended wallet (DID differs)", func(t *testing.T) {
				otherIssuedVC := vc.VerifiableCredential{
					Issuer:  issuerDID.URI(),
					Context: issuedVC.Context,
					Type:    issuedVC.Type,
					CredentialSubject: []map[string]any{
						{
							"id": "did:nuts:other-wallet",
						},
					},
				}

				service := requireNewTestHandler(t, keyResolver)
				otherOffer, err := service.createOffer(ctx, otherIssuedVC, preAuthCode)
				require.NoError(t, err)
				accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
				require.NoError(t, err)

				otherConfigID := otherOffer.CredentialConfigurationIds[0]
				invalidRequest := createRequest(createHeaders(), createClaims(""), otherConfigID)

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
				accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
				require.NoError(t, err)

				invalidRequest := createRequest(createHeaders(), createClaims(""), configID)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - key not found in DID document")
				assert.Nil(t, response)
			})
			t.Run("typ header missing", func(t *testing.T) {
				headers := createHeaders()
				headers["typ"] = ""
				invalidRequest := createRequest(headers, createClaims(""), configID)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid JWT typ header (expected 'openid4vci-proof+jwt', got '')")
				assert.Nil(t, response)
			})
			t.Run("typ header invalid", func(t *testing.T) {
				headers := createHeaders()
				delete(headers, "typ") // causes JWT library to set it to default ("JWT")
				invalidRequest := createRequest(headers, createClaims(""), configID)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid JWT typ header (expected 'openid4vci-proof+jwt', got 'JWT')")
				assert.Nil(t, response)
			})
			t.Run("aud header doesn't match issuer identifier", func(t *testing.T) {
				claims := createClaims("")
				claims["aud"] = "https://example.com/someone-else"
				invalidRequest := createRequest(createHeaders(), claims, configID)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - audience doesn't match credential issuer (aud=[https://example.com/someone-else])")
				assert.Nil(t, response)
			})
		})
		t.Run("unknown nonce", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims("other"), configID)

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_nonce - invalid or expired nonce")
			assert.Nil(t, response)
		})
	})
	t.Run("unknown access token", func(t *testing.T) {
		service := requireNewTestHandler(t, keyResolver)

		response, err := service.HandleCredentialRequest(ctx, validRequest, accessToken)

		assertProtocolError(t, err, http.StatusUnauthorized, "invalid_token - unknown access token")
		assert.Nil(t, response)
	})
	t.Run("credential issuer does not match", func(t *testing.T) {
		store := storage.NewTestInMemorySessionDatabase(t)
		service, err := NewOpenIDHandler(issuerDID, issuerIdentifier, definitionsDIR, &http.Client{}, keyResolver, store)
		require.NoError(t, err)
		_, err = service.(*openidHandler).createOffer(ctx, issuedVC, preAuthCode)
		require.NoError(t, err)
		accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
		require.NoError(t, err)
		nonce, err := service.HandleNonceRequest(ctx)
		require.NoError(t, err)
		request := createRequest(createHeaders(), createClaims(nonce), configID)

		otherService, err := NewOpenIDHandler(did.MustParseDID("did:nuts:other"), "http://example.com/other", definitionsDIR, &http.Client{}, keyResolver, store)
		require.NoError(t, err)
		response, err := otherService.HandleCredentialRequest(ctx, request, accessToken)

		assertProtocolError(t, err, http.StatusBadRequest, "invalid_credential_request - credential issuer does not match given issuer")
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

		accessToken, err := service.HandleAccessTokenRequest(audit.TestContext(), "code")

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
		accessToken, err := otherService.HandleAccessTokenRequest(audit.TestContext(), "code")

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

		accessToken, err := service.HandleAccessTokenRequest(audit.TestContext(), "code")

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_grant - unknown pre-authorized code")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		assert.Empty(t, accessToken)
	})
}

func Test_memoryIssuer_HandleNonceRequest(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		service := requireNewTestHandler(t, nil)

		nonce, err := service.HandleNonceRequest(ctx)

		require.NoError(t, err)
		assert.NotEmpty(t, nonce)
	})
}

func Test_memoryIssuer_validateProof_metadataDriven(t *testing.T) {
	keyStore := crypto.NewMemoryCryptoInstance(t)
	ctx := audit.TestContext()
	_, signerKey, _ := keyStore.New(ctx, crypto.StringNamingFunc(keyID))
	ctrl := gomock.NewController(t)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().ResolveKeyByID(keyID, nil, resolver.NutsSigningKeyType).AnyTimes().Return(signerKey, nil)

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
	createProofs := func(headers, claims map[string]interface{}) *openid4vci.CredentialRequestProofs {
		proof, err := keyStore.SignJWT(ctx, claims, headers, headers["kid"].(string))
		require.NoError(t, err)
		return &openid4vci.CredentialRequestProofs{
			Jwt: []string{proof},
		}
	}

	const preAuthCode = "some-secret-code"

	t.Run("standalone nonce from Nonce Endpoint is accepted", func(t *testing.T) {
		service := requireNewTestHandler(t, keyResolver)
		_, err := service.createOffer(ctx, issuedVC, preAuthCode)
		require.NoError(t, err)
		accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
		require.NoError(t, err)

		// Get a standalone nonce
		standaloneNonce, err := service.HandleNonceRequest(ctx)
		require.NoError(t, err)

		configID := "ExampleCredential_ldp_vc"
		request := openid4vci.CredentialRequest{
			CredentialConfigurationId: configID,
			Proofs:                    createProofs(createHeaders(), createClaims(standaloneNonce)),
		}

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		require.NoError(t, err)
		require.NotNil(t, response)
	})
	t.Run("proof skipped when credential config has no proof_types_supported", func(t *testing.T) {
		// Create a handler with a credential config that lacks proof_types_supported
		tmpDir := t.TempDir()
		noProofDef := `{
			"format": "ldp_vc",
			"cryptographic_binding_methods_supported": ["did:nuts"],
			"credential_definition": {
				"@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/credentials/v1"],
				"type": ["VerifiableCredential", "NoProofCredential"]
			}
		}`
		err := os.WriteFile(filepath.Join(tmpDir, "NoProofCredential.json"), []byte(noProofDef), 0644)
		require.NoError(t, err)

		service, err := NewOpenIDHandler(issuerDID, issuerIdentifier, tmpDir, &http.Client{}, keyResolver, storage.NewTestInMemorySessionDatabase(t))
		require.NoError(t, err)
		handler := service.(*openidHandler)

		noProofVC := vc.VerifiableCredential{
			Issuer: issuerDID.URI(),
			CredentialSubject: []map[string]any{
				{"id": holderDID.String()},
			},
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
				ssi.MustParseURI("https://example.com/credentials/v1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
				ssi.MustParseURI("NoProofCredential"),
			},
		}

		_, err = handler.createOffer(ctx, noProofVC, preAuthCode)
		require.NoError(t, err)
		accessToken, err := handler.HandleAccessTokenRequest(ctx, preAuthCode)
		require.NoError(t, err)

		// Request without proof should succeed
		request := openid4vci.CredentialRequest{
			CredentialConfigurationId: "NoProofCredential_ldp_vc",
		}

		response, err := handler.HandleCredentialRequest(ctx, request, accessToken)

		require.NoError(t, err)
		require.NotNil(t, response)
	})
	t.Run("non-string nonce claim returns invalid_proof", func(t *testing.T) {
		service := requireNewTestHandler(t, keyResolver)
		_, err := service.createOffer(ctx, issuedVC, preAuthCode)
		require.NoError(t, err)
		accessToken, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
		require.NoError(t, err)

		// Get a standalone nonce but put a number in the claim instead
		_, err = service.HandleNonceRequest(ctx)
		require.NoError(t, err)

		configID := "ExampleCredential_ldp_vc"
		claimsWithNumericNonce := map[string]interface{}{
			"aud":   issuerIdentifier,
			"iat":   time.Now().Unix(),
			"nonce": 12345, // non-string
		}
		request := openid4vci.CredentialRequest{
			CredentialConfigurationId: configID,
			Proofs:                    createProofs(createHeaders(), claimsWithNumericNonce),
		}

		_, err = service.HandleCredentialRequest(ctx, request, accessToken)

		assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - nonce claim is not a string")
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

func Test_deepcopyMap(t *testing.T) {
	t.Run("mutation of copy does not affect original", func(t *testing.T) {
		src := map[string]map[string]interface{}{
			"config1": {
				"format": "ldp_vc",
				"credential_definition": map[string]interface{}{
					"type": []interface{}{"VerifiableCredential"},
				},
			},
		}

		dst := deepcopyMap(src)
		credDef := dst["config1"]["credential_definition"].(map[string]interface{})
		credDef["type"] = []interface{}{"Mutated"}

		srcCredDef := src["config1"]["credential_definition"].(map[string]interface{})
		assert.Equal(t, []interface{}{"VerifiableCredential"}, srcCredDef["type"])
	})
}

func Test_matchesCredential(t *testing.T) {
	t.Run("matches on type and context", func(t *testing.T) {
		config := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential", "NutsOrganizationCredential"},
			},
		}
		cred := vc.VerifiableCredential{
			Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://nuts.nl/credentials/v1")},
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("NutsOrganizationCredential")},
		}

		assert.True(t, matchesCredential(config, cred))
	})
	t.Run("does not match on type mismatch", func(t *testing.T) {
		config := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential", "OtherCredential"},
			},
		}
		cred := vc.VerifiableCredential{
			Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("NutsOrganizationCredential")},
		}

		assert.False(t, matchesCredential(config, cred))
	})
	t.Run("does not match on context mismatch", func(t *testing.T) {
		config := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://other.example.com/v1"},
				"type":     []interface{}{"VerifiableCredential"},
			},
		}
		cred := vc.VerifiableCredential{
			Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
		}

		assert.False(t, matchesCredential(config, cred))
	})
}

func Test_generateCredentialConfigID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		defMap := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"type": []interface{}{"VerifiableCredential", "NutsOrganizationCredential"},
			},
		}
		id, err := generateCredentialConfigID(defMap)
		require.NoError(t, err)
		assert.Equal(t, "NutsOrganizationCredential_ldp_vc", id)
	})
	t.Run("missing format", func(t *testing.T) {
		defMap := map[string]interface{}{
			"credential_definition": map[string]interface{}{
				"type": []interface{}{"VerifiableCredential"},
			},
		}
		_, err := generateCredentialConfigID(defMap)
		assert.EqualError(t, err, "credential definition missing 'format' field")
	})
	t.Run("missing credential_definition", func(t *testing.T) {
		defMap := map[string]interface{}{
			"format": "ldp_vc",
		}
		_, err := generateCredentialConfigID(defMap)
		assert.EqualError(t, err, "credential definition missing 'credential_definition' field")
	})
	t.Run("missing type", func(t *testing.T) {
		defMap := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{},
		}
		_, err := generateCredentialConfigID(defMap)
		assert.EqualError(t, err, "credential definition missing 'type' field")
	})
	t.Run("empty type array", func(t *testing.T) {
		defMap := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"type": []interface{}{},
			},
		}
		_, err := generateCredentialConfigID(defMap)
		assert.EqualError(t, err, "credential definition missing 'type' field")
	})
	t.Run("only VerifiableCredential type falls back", func(t *testing.T) {
		defMap := map[string]interface{}{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"type": []interface{}{"VerifiableCredential"},
			},
		}
		id, err := generateCredentialConfigID(defMap)
		require.NoError(t, err)
		assert.Equal(t, "VerifiableCredential_ldp_vc", id)
	})
}
