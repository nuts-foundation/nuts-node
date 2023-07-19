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
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
	"time"
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
		CredentialIssuer: issuerDID.String(),
		Credentials:      offeredCredential(),
		Grants: map[string]interface{}{
			"some-other-grant": map[string]interface{}{},
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": "code",
			},
		},
	}
	metadata := openid4vci.CredentialIssuerMetadata{
		CredentialIssuer:   issuerDID.String(),
		CredentialEndpoint: "credential-endpoint",
	}
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nonce := "nonsens"
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(metadata)
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(&openid4vci.TokenResponse{
			AccessToken: "access-token",
			CNonce:      nonce,
			ExpiresIn:   0,
			TokenType:   "bearer",
		}, nil)
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), "access-token").
			Return(&vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("http://example.org/credentials/V1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("HumanCredential")},
				Issuer:  issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"aud":   issuerDID.String(),
			"iat":   int64(1735689600),
			"nonce": nonce,
		}, gomock.Any(), "key-id").Return("signed-jwt", nil)
		keyResolver := vdrTypes.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, vdrTypes.AssertionMethod).Return(ssi.MustParseURI("key-id"), nil, nil)

		nowFunc = func() time.Time {
			return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		}

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
			offer := openid4vci.CredentialOffer{Credentials: offeredCredential()}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
		t.Run("no pre-authorized grant", func(t *testing.T) {
			offer := openid4vci.CredentialOffer{
				Credentials: offeredCredential(),
				Grants: map[string]interface{}{
					"some-other-grant": nil,
				},
			}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
		t.Run("invalid pre-authorized grant", func(t *testing.T) {
			offer := openid4vci.CredentialOffer{
				Credentials: offeredCredential(),
				Grants: map[string]interface{}{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
						"pre-authorized_code": nil,
					},
				},
			}
			err := w.HandleCredentialOffer(audit.TestContext(), offer)
			require.EqualError(t, err, "invalid_grant - couldn't find (valid) pre-authorized code grant in credential offer")
		})
	})
	t.Run("error - too many credentials in offer", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		offer := openid4vci.CredentialOffer{
			Credentials: []openid4vci.OfferedCredential{
				offeredCredential()[0],
				offeredCredential()[0],
			},
		}
		err := w.HandleCredentialOffer(audit.TestContext(), offer).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - there must be exactly 1 credential in credential offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - access token request fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(nil, errors.New("request failed"))

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "invalid_token - unable to request access token: request failed")
	})
	t.Run("error - empty access token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&openid4vci.TokenResponse{}, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "invalid_token - access_token is missing")
	})
	t.Run("error - empty c_nonce", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		issuerAPIClient := openid4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&openid4vci.TokenResponse{AccessToken: "foo"}, nil)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "invalid_token - c_nonce is missing")
	})
	t.Run("error - no credentials in offer", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{}).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - there must be exactly 1 credential in credential offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - can't issuer client (metadata can't be loaded)", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{
			CredentialIssuer: "http://localhost:87632",
			Credentials:      offeredCredential(),
			Grants: map[string]interface{}{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
					"pre-authorized_code": "foo",
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
		issuerAPIClient.EXPECT().Metadata().Return(metadata)
		issuerAPIClient.EXPECT().RequestAccessToken(gomock.Any(), gomock.Any()).Return(&openid4vci.TokenResponse{AccessToken: "access-token", CNonce: "c_nonce"}, nil)
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(&vc.VerifiableCredential{
			Context: offer.CredentialDefinition.Context,
			Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
		}, nil)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		keyResolver := vdrTypes.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(holderDID, nil, vdrTypes.AssertionMethod)

		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, jwtSigner, keyResolver).(*openidHandler)
		w.issuerClientCreator = func(_ context.Context, _ core.HTTPRequestDoer, _ string) (openid4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.EqualError(t, err, "invalid_request - received credential does not match offer: credential does not match credential_definition: type mismatch")
	})
	t.Run("error - unsupported format", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{
			Credentials: []openid4vci.OfferedCredential{{Format: "not supported"}},
		}).(openid4vci.Error)

		assert.EqualError(t, err, "unsupported_credential_type - credential offer: unsupported format 'not supported'")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - credentialSubject not allowed in offer", func(t *testing.T) {
		w := NewOpenIDHandler(holderDID, "https://holder.example.com", &http.Client{}, nil, nil, nil)
		credentials := offeredCredential()
		credentials[0].CredentialDefinition.CredentialSubject = new(map[string]interface{})

		err := w.HandleCredentialOffer(audit.TestContext(), openid4vci.CredentialOffer{Credentials: credentials}).(openid4vci.Error)

		assert.EqualError(t, err, "invalid_request - credential offer: invalid credential_definition: credentialSubject not allowed in offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
}

// offeredCredential returns a structure that can be used as CredentialOffer.Credentials,
func offeredCredential() []openid4vci.OfferedCredential {
	return []openid4vci.OfferedCredential{{
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
	}}
}
