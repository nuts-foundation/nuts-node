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
	createProof := func(headers, claims map[string]interface{}) *openid4vci.CredentialRequestProof {
		proof, err := keyStore.SignJWT(ctx, claims, headers, headers["kid"].(string))
		require.NoError(t, err)
		return &openid4vci.CredentialRequestProof{
			Jwt:       proof,
			ProofType: openid4vci.ProofTypeJWT,
		}
	}
	createRequest := func(headers, claims map[string]interface{}, configID string) openid4vci.CredentialRequest {
		return openid4vci.CredentialRequest{
			CredentialConfigurationId: configID,
			Proof:                     createProof(headers, claims),
		}
	}

	const preAuthCode = "some-secret-code"

	service := requireNewTestHandler(t, keyResolver)
	offer, err := service.createOffer(ctx, issuedVC, preAuthCode)
	require.NoError(t, err)
	accessToken, cNonce, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
	require.NoError(t, err)
	configID := offer.CredentialConfigurationIds[0]
	validRequest := createRequest(createHeaders(), createClaims(cNonce), configID)

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
			Proof: createProof(createHeaders(), createClaims(cNonce)),
		}

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_credential_request - credential request must contain credential_configuration_id")
	})
	t.Run("error - unknown credential_configuration_id", func(t *testing.T) {
		request := createRequest(createHeaders(), createClaims(cNonce), "NonExistent_ldp_vc")

		response, err := service.HandleCredentialRequest(ctx, request, accessToken)

		assert.Nil(t, response)
		require.ErrorAs(t, err, new(openid4vci.Error))
		assert.Equal(t, openid4vci.UnknownCredentialConfiguration, err.(openid4vci.Error).Code)
	})
	t.Run("proof validation", func(t *testing.T) {
		t.Run("unsupported proof type", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
			invalidRequest.Proof.ProofType = "not-supported"

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - proof type not supported")
			assert.Nil(t, response)
		})
		t.Run("jwt", func(t *testing.T) {
			t.Run("missing proof", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
				invalidRequest.Proof = nil

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - missing proof")
				assert.Nil(t, response)
			})
			t.Run("missing proof returns error with new c_nonce", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
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
				invalidRequest := createRequest(createHeaders(), createClaims(""), configID)
				invalidRequest.Proof.Jwt = "not a JWT"

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid compact serialization format: invalid number of segments")
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
				accessToken, _, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
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
				accessToken, _, err := service.HandleAccessTokenRequest(ctx, preAuthCode)
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

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - missing typ header")
				assert.Nil(t, response)
			})
			t.Run("typ header invalid", func(t *testing.T) {
				headers := createHeaders()
				delete(headers, "typ") // causes JWT library to set it to default ("JWT")
				invalidRequest := createRequest(headers, createClaims(""), configID)

				response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_proof - invalid typ claim (expected: openid4vci-proof+jwt): JWT")
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

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_nonce - unknown nonce")
			assert.Nil(t, response)
			// Per Section 8.3.1.2: invalid_nonce MUST include a fresh c_nonce
			require.ErrorAs(t, err, new(openid4vci.Error))
			assert.NotNil(t, err.(openid4vci.Error).CNonce)
			assert.NotNil(t, err.(openid4vci.Error).CNonceExpiresIn)
		})
		t.Run("wrong nonce", func(t *testing.T) {
			_, err := service.createOffer(ctx, issuedVC, "other")
			require.NoError(t, err)
			_, cNonce, err := service.HandleAccessTokenRequest(ctx, "other")
			require.NoError(t, err)
			invalidRequest := createRequest(createHeaders(), createClaims(cNonce), configID)

			response, err := service.HandleCredentialRequest(ctx, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_nonce - nonce not valid for access token")
			assert.Nil(t, response)
		})
	})
	t.Run("unknown access token", func(t *testing.T) {
		service := requireNewTestHandler(t, keyResolver)

		response, err := service.HandleCredentialRequest(ctx, validRequest, accessToken)

		assertProtocolError(t, err, http.StatusUnauthorized, "invalid_token - unknown access token")
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
