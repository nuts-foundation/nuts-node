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

package openid4vci

import (
	"context"
	crypt "crypto"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"path"
	"testing"
	"time"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")
var holderDID = did.MustParseDID("did:nuts:holder")
var issuerIdentifier = baseURL + "/" + issuerDID.String()
var keyID = holderDID.String() + "#1"

const baseURL = "https://example.com"

var issuedVC = vc.VerifiableCredential{
	Issuer: issuerDID.URI(),
	CredentialSubject: []interface{}{
		map[string]interface{}{
			"id": holderDID.String(),
		},
	},
}

func Test_memoryIssuer_Metadata(t *testing.T) {
	metadata, err := createIssuer(t, nil).Metadata(issuerDID)

	require.NoError(t, err)
	assert.Equal(t, oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:     "https://example.com/did:nuts:issuer",
		CredentialEndpoint:   "https://example.com/did:nuts:issuer/issuer/oidc4vci/credential",
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}, metadata)
}

func Test_memoryIssuer_ProviderMetadata(t *testing.T) {
	metadata, err := createIssuer(t, nil).ProviderMetadata(issuerDID)

	require.NoError(t, err)
	assert.Equal(t, oidc4vci.ProviderMetadata{
		Issuer:        "https://example.com/did:nuts:issuer",
		TokenEndpoint: "https://example.com/did:nuts:issuer/oidc/token",
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
	keyResolver := types.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().ResolveSigningKey(keyID, nil).AnyTimes().Return(signerKey.Public(), nil)

	createHeaders := func() map[string]interface{} {
		return map[string]interface{}{
			"typ": oidc4vci.JWTTypeOpenID4VCIProof,
			"kid": keyID,
		}
	}
	createClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"aud": issuerIdentifier,
			"iat": time.Now().Unix(),
		}
	}
	createRequest := func(headers, claims map[string]interface{}) oidc4vci.CredentialRequest {
		proof, err := keyStore.SignJWT(ctx, claims, headers, headers["kid"])
		require.NoError(t, err)
		return oidc4vci.CredentialRequest{
			Format: oidc4vci.VerifiableCredentialJSONLDFormat,
			Proof: &oidc4vci.CredentialRequestProof{
				Jwt:       proof,
				ProofType: oidc4vci.ProofTypeJWT,
			},
		}
	}
	validRequest := createRequest(createHeaders(), createClaims())

	const preAuthCode = "some-secret-code"

	issuer := createIssuer(t, keyResolver)
	_, err := issuer.createOffer(ctx, issuedVC, preAuthCode)
	require.NoError(t, err)
	accessToken, err := issuer.HandleAccessTokenRequest(ctx, issuerDID, preAuthCode)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)
		response, err := issuer.HandleCredentialRequest(ctx, issuerDID, validRequest, accessToken)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, issuerDID.URI(), response.Issuer)
		auditLogs.AssertContains(t, "VCR", "VerifiableCredentialRetrievedEvent", audit.TestActor, "VC retrieved by wallet over OIDC4VCI")
	})
	t.Run("proof validation", func(t *testing.T) {
		t.Run("unsupported proof type", func(t *testing.T) {
			invalidRequest := createRequest(createHeaders(), createClaims())
			invalidRequest.Proof.ProofType = "not-supported"

			response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

			assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - proof type not supported")
			assert.Nil(t, response)
		})
		t.Run("jwt", func(t *testing.T) {
			t.Run("missing proof", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims())
				invalidRequest.Proof = nil

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - missing proof")
				assert.Nil(t, response)
			})
			t.Run("invalid JWT", func(t *testing.T) {
				invalidRequest := createRequest(createHeaders(), createClaims())
				invalidRequest.Proof.Jwt = "not a JWT"

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - invalid compact serialization format: invalid number of segments")
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

				issuer := createIssuer(t, keyResolver)
				_, err := issuer.createOffer(ctx, otherIssuedVC, preAuthCode)
				require.NoError(t, err)
				accessToken, err := issuer.HandleAccessTokenRequest(ctx, issuerDID, preAuthCode)
				require.NoError(t, err)

				invalidRequest := createRequest(createHeaders(), createClaims())

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - credential offer was signed by other DID than intended wallet: did:nuts:holder#1")
				assert.Nil(t, response)
			})
			t.Run("signing key is unknown", func(t *testing.T) {
				keyResolver := types.NewMockKeyResolver(ctrl)
				keyResolver.EXPECT().ResolveSigningKey(keyID, nil).AnyTimes().Return(nil, types.ErrKeyNotFound)
				issuer := createIssuer(t, keyResolver)
				_, err := issuer.createOffer(ctx, issuedVC, preAuthCode)
				require.NoError(t, err)
				accessToken, err := issuer.HandleAccessTokenRequest(ctx, issuerDID, preAuthCode)
				require.NoError(t, err)

				invalidRequest := createRequest(createHeaders(), createClaims())

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - key not found in DID document")
				assert.Nil(t, response)
			})
			t.Run("typ header missing", func(t *testing.T) {
				headers := createHeaders()
				headers["typ"] = ""
				invalidRequest := createRequest(headers, createClaims())

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - missing typ header")
				assert.Nil(t, response)
			})
			t.Run("typ header invalid", func(t *testing.T) {
				headers := createHeaders()
				delete(headers, "typ") // causes JWT library to set it to default ("JWT")
				invalidRequest := createRequest(headers, createClaims())

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - invalid typ claim (expected: openid4vci-proof+jwt): JWT")
				assert.Nil(t, response)
			})
			t.Run("aud header doesn't match issuer identifier", func(t *testing.T) {
				claims := createClaims()
				claims["aud"] = "https://example.com/someone-else"
				invalidRequest := createRequest(createHeaders(), claims)

				response, err := issuer.HandleCredentialRequest(ctx, issuerDID, invalidRequest, accessToken)

				assertProtocolError(t, err, http.StatusBadRequest, "invalid_or_missing_proof - audience doesn't match credential issuer (aud=[https://example.com/someone-else])")
				assert.Nil(t, response)
			})
		})
	})

	t.Run("unknown access token", func(t *testing.T) {
		issuer := createIssuer(t, keyResolver)

		response, err := issuer.HandleCredentialRequest(ctx, issuerDID, validRequest, accessToken)

		assertProtocolError(t, err, http.StatusBadRequest, "invalid_token - unknown access token")
		assert.Nil(t, response)
	})
}

func Test_memoryIssuer_OfferCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := oidc4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(nil)
		issuer := createIssuer(t, nil)
		issuer.walletClientCreator = func(_ context.Context, _ *http.Client, _ string) (oidc4vci.WalletAPIClient, error) {
			return wallet, nil
		}

		err := issuer.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.NoError(t, err)
	})
	t.Run("client offer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := oidc4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().Metadata().Return(oidc4vci.OAuth2ClientMetadata{CredentialOfferEndpoint: "here-please"})
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(errors.New("failed"))
		issuer := createIssuer(t, nil)
		issuer.walletClientCreator = func(_ context.Context, _ *http.Client, _ string) (oidc4vci.WalletAPIClient, error) {
			return wallet, nil
		}

		err := issuer.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.EqualError(t, err, "unable to offer credential (client-metadata-url=here-please): failed")
	})
}

func Test_memoryIssuer_HandleAccessTokenRequest(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		issuer := createIssuer(t, nil)
		_, err := issuer.createOffer(ctx, issuedVC, "code")
		require.NoError(t, err)

		accessToken, err := issuer.HandleAccessTokenRequest(audit.TestContext(), issuerDID, "code")

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})
	t.Run("unknown pre-authorized code", func(t *testing.T) {
		issuer := createIssuer(t, nil)
		_, err := issuer.createOffer(ctx, issuedVC, "some-other-code")
		require.NoError(t, err)

		accessToken, err := issuer.HandleAccessTokenRequest(audit.TestContext(), issuerDID, "code")

		var protocolError oidc4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_grant - unknown pre-authorized code")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		assert.Empty(t, accessToken)
	})
}

func assertProtocolError(t *testing.T, err error, statusCode int, message string) {
	var protocolError oidc4vci.Error
	require.ErrorAs(t, err, &protocolError)
	assert.EqualError(t, protocolError, message)
	assert.Equal(t, statusCode, protocolError.StatusCode)
}

func createIssuer(t *testing.T, keyResolver types.KeyResolver) *issuer {
	store := storage.CreateTestBBoltStore(t, path.Join(io.TestDirectory(t), "issuer.db"))
	return New(baseURL, nil, time.Second, keyResolver, NewStoabsStore(store)).(*issuer)
}
