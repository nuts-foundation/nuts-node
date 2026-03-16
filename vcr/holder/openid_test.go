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

package holder

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var holderDID = did.MustParseDID("did:nuts:holder")
var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestNewOIDCWallet(t *testing.T) {
	w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)
	assert.NotNil(t, w)
}

func Test_wallet_Metadata(t *testing.T) {
	w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

	metadata := w.Metadata()

	assert.Equal(t, openid4vci.OAuth2ClientMetadata{
		CredentialOfferEndpoint: "https://holder.example.com/openid4vci/credential_offer",
	}, metadata)
}

func Test_wallet_HandleCredentialOffer(t *testing.T) {
	credentialOffer := openid4vci.CredentialOffer{
		CredentialIssuer:           issuerDID.String(),
		CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
		Grants: &openid4vci.CredentialOfferGrants{
			PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
				PreAuthorizedCode: "code",
			},
		},
	}
	metadata := openid4vci.CredentialIssuerMetadata{
		CredentialIssuer:   issuerDID.String(),
		CredentialEndpoint: "credential-endpoint",
		CredentialConfigurationsSupported: map[string]map[string]interface{}{
			"ExampleCredential_ldp_vc": {
				"format": "ldp_vc",
				"credential_definition": map[string]interface{}{
					"@context": []interface{}{
						"https://www.w3.org/2018/credentials/v1",
						"https://example.com/credentials/v1",
					},
					"type": []interface{}{
						"VerifiableCredential",
						"ExampleCredential",
					},
				},
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadata).AnyTimes()
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)
		// Verify that the holder sends credential_configuration_id in the credential request
		expectedRequest := openid4vci.CredentialRequest{
			CredentialConfigurationID: "ExampleCredential_ldp_vc",
			Proofs: &openid4vci.CredentialRequestProofs{
				Jwt: []string{"signed-jwt"},
			},
		}
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), expectedRequest, "access-token").
			Return(&vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://example.com/credentials/v1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("ExampleCredential")},
				Issuer:  issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"iss": holderDID.String(),
			"aud": issuerDID.String(),
			"iat": int64(1735689600),
		}, gomock.Any(), "key-id").Return("signed-jwt", nil)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		nowFunc = func() time.Time {
			return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		t.Cleanup(func() { nowFunc = time.Now })

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, credentialStore, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).Return(nil)

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.NoError(t, err)
	})
	t.Run("pre-authorized code grant", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		t.Run("no grants", func(t *testing.T) {
			offer := openid4vci.CredentialOffer{CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"}}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
		t.Run("no pre-authorized grant", func(t *testing.T) {
			offer := openid4vci.CredentialOffer{
				CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
				Grants:                     nil,
			}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
		t.Run("empty pre-authorized code", func(t *testing.T) {
			offer := openid4vci.CredentialOffer{
				CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
				Grants: &openid4vci.CredentialOfferGrants{
					PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
						PreAuthorizedCode: "",
					},
				},
			}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
	})
	t.Run("error - too many credential_configuration_ids in offer", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		offer := openid4vci.CredentialOffer{
			CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc", "OtherCredential_ldp_vc"},
		}
		err := w.HandleCredentialOffer(audit.TestContext(), offer).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - there must be exactly 1 credential_configuration_id in credential offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - credential_configuration_id not found in metadata", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		emptyMetadata := openid4vci.CredentialIssuerMetadata{
			CredentialIssuer:                  issuerDID.String(),
			CredentialEndpoint:                "credential-endpoint",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{},
		}
		issuerAPIClient.EXPECT().Metadata().Return(emptyMetadata).AnyTimes()

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.ErrorContains(t, err, "credential_configuration_id 'ExampleCredential_ldp_vc' not found in issuer metadata")
	})
	t.Run("error - credential configuration missing format", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		metadataNoFormat := openid4vci.CredentialIssuerMetadata{
			CredentialIssuer:   issuerDID.String(),
			CredentialEndpoint: "credential-endpoint",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"ExampleCredential_ldp_vc": {
					"credential_definition": map[string]interface{}{
						"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
						"type":     []interface{}{"VerifiableCredential"},
					},
				},
			},
		}
		issuerAPIClient.EXPECT().Metadata().Return(metadataNoFormat).AnyTimes()

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.ErrorContains(t, err, "credential configuration 'ExampleCredential_ldp_vc' is missing 'format' field")
	})
	t.Run("error - access token request fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadata).AnyTimes()
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(nil, errors.New("request failed"))

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "server_error - unable to request access token: request failed")
	})
	t.Run("error - empty access token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadata).AnyTimes()
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&oauth.TokenResponse{}, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "server_error - access_token is missing")
	})
	t.Run("error - no credential_configuration_ids in offer", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{}).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - there must be exactly 1 credential_configuration_id in credential offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - can't issuer client (metadata can't be loaded)", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{
			CredentialIssuer:           "http://localhost:87632",
			CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
			Grants: &openid4vci.CredentialOfferGrants{
				PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
					PreAuthorizedCode: "foo",
				},
			},
		})

		assert.EqualError(t, err, "server_error - unable to create issuer client: unable to load Credential Issuer Metadata (identifier=http://localhost:87632): "+
			"http request error: Get \"http://localhost:87632/.well-known/openid-credential-issuer\": dial tcp: address 87632: invalid port")
	})
	t.Run("error - credential does not match offer", func(t *testing.T) {
		offer := offeredCredential()[0]
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadata).AnyTimes()
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&oauth.TokenResponse{AccessToken: "access-token"}, nil)
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(&vc.VerifiableCredential{
			Context: offer.CredentialDefinition.Context,
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
		}, nil)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "invalid_request - received credential does not match offer: credential does not match credential_definition: type mismatch")
	})
	t.Run("error - unsupported format", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(openid4vci.CredentialIssuerMetadata{
			CredentialIssuer: issuerDID.String(),
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"TestCredential_unsupported": {
					"format": "not supported",
				},
			},
		})

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{
			CredentialConfigurationIDs: []string{"TestCredential_unsupported"},
			Grants: &openid4vci.CredentialOfferGrants{
				PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
					PreAuthorizedCode: "foo",
				},
			},
		}).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - credential offer: unsupported format 'not supported'")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("credentialSubject in metadata does not block offer processing", func(t *testing.T) {
		// v1.0 Appendix A.1.2: credentialSubject is allowed in metadata credential_configurations_supported
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		metadataWithSubject := openid4vci.CredentialIssuerMetadata{
			CredentialIssuer: issuerDID.String(),
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"TestCredential_ldp_vc": {
					"format": "ldp_vc",
					"credential_definition": map[string]interface{}{
						"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
						"type":              []interface{}{"VerifiableCredential"},
						"credentialSubject": map[string]interface{}{},
					},
				},
			},
		}
		issuerAPIClient.EXPECT().Metadata().Return(metadataWithSubject).AnyTimes()
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&oauth.TokenResponse{AccessToken: "access-token"}, nil)
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(&vc.VerifiableCredential{
			Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
			Issuer:  issuerDID.URI(),
		}, nil)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("signed-jwt", nil)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)
		credentialStore := types.NewMockWriter(ctrl)
		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).Return(nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, credentialStore, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{
			CredentialConfigurationIDs: []string{"TestCredential_ldp_vc"},
			Grants: &openid4vci.CredentialOfferGrants{
				PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
					PreAuthorizedCode: "foo",
				},
			},
		})

		assert.NoError(t, err)
	})
}

func Test_wallet_RetrieveCredentialWithNonceEndpoint(t *testing.T) {
	credentialOffer := openid4vci.CredentialOffer{
		CredentialIssuer:           issuerDID.String(),
		CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
		Grants: &openid4vci.CredentialOfferGrants{
			PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
				PreAuthorizedCode: "code",
			},
		},
	}
	nonce := "nonce-from-endpoint"
	metadataWithNonce := openid4vci.CredentialIssuerMetadata{
		CredentialIssuer:   issuerDID.String(),
		CredentialEndpoint: "credential-endpoint",
		NonceEndpoint:      "https://issuer.example/nonce",
		CredentialConfigurationsSupported: map[string]map[string]interface{}{
			"ExampleCredential_ldp_vc": {
				"format": "ldp_vc",
				"credential_definition": map[string]interface{}{
					"@context": []interface{}{
						"https://www.w3.org/2018/credentials/v1",
						"https://example.com/credentials/v1",
					},
					"type": []interface{}{
						"VerifiableCredential",
						"ExampleCredential",
					},
				},
			},
		},
	}

	t.Run("uses Nonce Endpoint when advertised", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataWithNonce).AnyTimes()
		issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: nonce}, nil)
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)
		expectedRequest := openid4vci.CredentialRequest{
			CredentialConfigurationID: "ExampleCredential_ldp_vc",
			Proofs: &openid4vci.CredentialRequestProofs{
				Jwt: []string{"signed-jwt"},
			},
		}
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), expectedRequest, "access-token").
			Return(&vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://example.com/credentials/v1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("ExampleCredential")},
				Issuer:  issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		nowFunc = func() time.Time {
			return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		t.Cleanup(func() { nowFunc = time.Now })
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"iss":   holderDID.String(),
			"aud":   issuerDID.String(),
			"iat":   int64(1767225600),
			"nonce": nonce,
		}, gomock.Any(), "key-id").Return("signed-jwt", nil)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, credentialStore, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).Return(nil)

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.NoError(t, err)
	})
	t.Run("retries on invalid_nonce", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataWithNonce).AnyTimes()
		// First nonce request → used in first attempt (which fails with invalid_nonce)
		// Second nonce request → used in retry (which succeeds)
		first := issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: "stale-nonce"}, nil)
		issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: nonce}, nil).After(first)
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)
		// First credential request (with stale nonce) fails with invalid_nonce
		firstCredReq := openid4vci.CredentialRequest{
			CredentialConfigurationID: "ExampleCredential_ldp_vc",
			Proofs:                    &openid4vci.CredentialRequestProofs{Jwt: []string{"signed-jwt-1"}},
		}
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), firstCredReq, "access-token").
			Return(nil, openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: http.StatusBadRequest})
		// Retry with fresh nonce succeeds
		retryCredReq := openid4vci.CredentialRequest{
			CredentialConfigurationID: "ExampleCredential_ldp_vc",
			Proofs:                    &openid4vci.CredentialRequestProofs{Jwt: []string{"signed-jwt-2"}},
		}
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), retryCredReq, "access-token").
			Return(&vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://example.com/credentials/v1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("ExampleCredential")},
				Issuer:  issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		nowFunc = func() time.Time {
			return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		t.Cleanup(func() { nowFunc = time.Now })
		// First attempt uses the stale nonce
		firstSign := jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"iss":   holderDID.String(),
			"aud":   issuerDID.String(),
			"iat":   int64(1767225600),
			"nonce": "stale-nonce",
		}, gomock.Any(), "key-id").Return("signed-jwt-1", nil)
		// Retry uses the fresh nonce
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"iss":   holderDID.String(),
			"aud":   issuerDID.String(),
			"iat":   int64(1767225600),
			"nonce": nonce,
		}, gomock.Any(), "key-id").Return("signed-jwt-2", nil).After(firstSign)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, credentialStore, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).Return(nil)

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.NoError(t, err)
	})
	t.Run("error - invalid_nonce retry also fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataWithNonce).AnyTimes()
		first := issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: "stale-nonce"}, nil)
		issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: "also-stale"}, nil).After(first)
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)
		// Both credential requests fail
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), "access-token").
			Return(nil, openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: http.StatusBadRequest})
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), "access-token").
			Return(nil, openid4vci.Error{Code: openid4vci.InvalidNonce, StatusCode: http.StatusBadRequest})

		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), "key-id").Return("signed-jwt", nil).Times(2)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "server_error - unable to retrieve credential: invalid_nonce")
	})
	t.Run("error - nonce endpoint request fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataWithNonce).AnyTimes()
		issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(nil, errors.New("nonce request failed"))
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&oauth.TokenResponse{AccessToken: "access-token"}, nil)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "server_error - unable to retrieve credential: unable to request nonce: nonce request failed")
	})
}

func Test_wallet_ProofSigningAlgValidation(t *testing.T) {
	credentialOffer := openid4vci.CredentialOffer{
		CredentialIssuer:           issuerDID.String(),
		CredentialConfigurationIDs: []string{"ExampleCredential_ldp_vc"},
		Grants: &openid4vci.CredentialOfferGrants{
			PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
				PreAuthorizedCode: "code",
			},
		},
	}
	t.Run("error - signing algorithm not supported by issuer", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		metadataAlgRestricted := openid4vci.CredentialIssuerMetadata{
			CredentialIssuer:   issuerDID.String(),
			CredentialEndpoint: "credential-endpoint",
			NonceEndpoint:      "https://issuer.example/nonce",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"ExampleCredential_ldp_vc": {
					"format": "ldp_vc",
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []interface{}{"ES384"},
						},
					},
					"credential_definition": map[string]interface{}{
						"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://example.com/credentials/v1"},
						"type":     []interface{}{"VerifiableCredential", "ExampleCredential"},
					},
				},
			},
		}
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataAlgRestricted).AnyTimes()
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)

		p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", &p256Key.PublicKey, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, crypto.NewMockJWTSigner(ctrl), keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "server_error - unable to retrieve credential: signing algorithm ES256 is not supported by issuer (supported: ES384)")
	})
	t.Run("ok - algorithm validation skipped when proof_types_supported absent", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		metadataNoProofTypes := openid4vci.CredentialIssuerMetadata{
			CredentialIssuer:   issuerDID.String(),
			CredentialEndpoint: "credential-endpoint",
			NonceEndpoint:      "https://issuer.example/nonce",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"ExampleCredential_ldp_vc": {
					"format": "ldp_vc",
					"credential_definition": map[string]interface{}{
						"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", "https://example.com/credentials/v1"},
						"type":     []interface{}{"VerifiableCredential", "ExampleCredential"},
					},
				},
			},
		}
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadataNoProofTypes).AnyTimes()
		nonce := "nonce-from-endpoint"
		issuerAPIClient.EXPECT().RequestNonce(gomock.Any()).Return(&openid4vci.NonceResponse{CNonce: nonce}, nil)
		tokenResponse := &oauth.TokenResponse{AccessToken: "access-token", TokenType: "bearer"}
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(tokenResponse, nil)
		expectedRequest := openid4vci.CredentialRequest{
			CredentialConfigurationID: "ExampleCredential_ldp_vc",
			Proofs:                    &openid4vci.CredentialRequestProofs{Jwt: []string{"signed-jwt"}},
		}
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), expectedRequest, "access-token").
			Return(&vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://example.com/credentials/v1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("ExampleCredential")},
				Issuer:  issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		nowFunc = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
		t.Cleanup(func() { nowFunc = time.Now })
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"iss":   holderDID.String(),
			"aud":   issuerDID.String(),
			"iat":   int64(1767225600),
			"nonce": nonce,
		}, gomock.Any(), "key-id").Return("signed-jwt", nil)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, resolver.NutsSigningKeyType).Return("key-id", nil, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, credentialStore, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).Return(nil)

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.NoError(t, err)
	})
}

// offeredCredential returns a resolved credential configuration for testing.
func offeredCredential() []openid4vci.OfferedCredential {
	return []openid4vci.OfferedCredential{{
		Format: vc.JSONLDCredentialProofFormat,
		CredentialDefinition: &openid4vci.CredentialDefinition{
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
				ssi.MustParseURI("https://example.com/credentials/v1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
				ssi.MustParseURI("ExampleCredential"),
			},
		},
	}}
}
