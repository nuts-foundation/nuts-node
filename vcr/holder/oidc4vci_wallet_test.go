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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

var holderDID = did.MustParseDID("did:nuts:holder")
var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestNewOIDCWallet(t *testing.T) {
	w := NewOIDCWallet(holderDID, "https://holder.example.com", nil, nil, nil, time.Second*5)
	assert.NotNil(t, w)
}

func Test_wallet_Metadata(t *testing.T) {
	w := NewOIDCWallet(holderDID, "https://holder.example.com", nil, nil, nil, time.Second*5)

	metadata := w.Metadata()

	assert.Equal(t, oidc4vci.OAuth2ClientMetadata{
		CredentialOfferEndpoint: "https://holder.example.com/wallet/oidc4vci/credential_offer",
	}, metadata)
}

func Test_wallet_HandleCredentialOffer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nonce := "nonsens"
		issuerAPIClient := oidc4vci.NewMockIssuerAPIClient(ctrl)
		issuerAPIClient.EXPECT().Metadata().Return(oidc4vci.CredentialIssuerMetadata{
			CredentialIssuer:   issuerDID.String(),
			CredentialEndpoint: "credential-endpoint",
		})
		issuerAPIClient.EXPECT().RequestAccessToken("urn:ietf:params:oauth:grant-type:pre-authorized_code", map[string]string{
			"pre-authorized_code": "code",
		}).Return(&oidc4vci.TokenResponse{
			AccessToken: "access-token",
			CNonce:      &nonce,
			ExpiresIn:   new(int),
			TokenType:   "bearer",
		}, nil)
		issuerAPIClient.EXPECT().RequestCredential(gomock.Any(), gomock.Any(), "access-token").
			Return(&vc.VerifiableCredential{Issuer: issuerDID.URI()}, nil)

		credentialStore := types.NewMockWriter(ctrl)
		jwtSigner := crypto.NewMockJWTSigner(ctrl)
		jwtSigner.EXPECT().SignJWT(gomock.Any(), map[string]interface{}{
			"aud":   issuerDID.String(),
			"iat":   int64(1735689600),
			"nonce": nonce,
		}, gomock.Any(), "key-id").Return("signed-jwt", nil)
		keyResolver := vdrTypes.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveSigningKeyID(holderDID, nil).Return("key-id", nil)

		nowFunc = func() time.Time {
			return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		}

		w := NewOIDCWallet(holderDID, "https://holder.example.com", credentialStore, jwtSigner, keyResolver, time.Second*5).(*wallet)
		w.issuerClientCreator = func(_ context.Context, httpClient *http.Client, credentialIssuerIdentifier string) (oidc4vci.IssuerAPIClient, error) {
			return issuerAPIClient, nil
		}
		credentialOffer := oidc4vci.CredentialOffer{
			CredentialIssuer: issuerDID.String(),
			Credentials: []map[string]interface{}{
				{
					"format": oidc4vci.VerifiableCredentialJSONLDFormat,
					"credential_definition": map[string]interface{}{
						"@context": []string{"a", "b"},
						"types":    []string{"VerifiableCredential", "HumanCredential"},
					},
				},
			},
			Grants: []map[string]interface{}{
				{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
						"pre-authorized_code": "code",
					},
				},
			},
		}

		vcStored := atomic.Pointer[bool]{}
		credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).DoAndReturn(func(_ vc.VerifiableCredential, _ *time.Time) error {
			vcStored.Store(new(bool))
			return nil
		})

		err := w.HandleCredentialOffer(audit.TestContext(), credentialOffer)

		require.NoError(t, err)
		test.WaitFor(t, func() (bool, error) {
			return vcStored.Load() != nil, nil
		}, 2*time.Second, "time-out waiting for VC to be stored")
	})
	t.Run("error - no credentials in offer", func(t *testing.T) {
		w := NewOIDCWallet(holderDID, "https://holder.example.com", nil, nil, nil, time.Second*5)

		err := w.HandleCredentialOffer(audit.TestContext(), oidc4vci.CredentialOffer{}).(oidc4vci.Error)

		assert.EqualError(t, err, "invalid_request - there must be at least 1 credential in credential offer")
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})
	t.Run("error - can't issuer client (metadata can't be loaded)", func(t *testing.T) {
		w := NewOIDCWallet(holderDID, "https://holder.example.com", nil, nil, nil, time.Second*5)

		err := w.HandleCredentialOffer(audit.TestContext(), oidc4vci.CredentialOffer{
			CredentialIssuer: "http://localhost:87632",
			Credentials: []map[string]interface{}{
				{
					"format": oidc4vci.VerifiableCredentialJSONLDFormat,
				},
			},
		})

		assert.EqualError(t, err, "unable to create issuer client: unable to load Credential Issuer Metadata (identifier=http://localhost:87632): "+
			"http request error (http://localhost:87632/.well-known/openid-credential-issuer): Get \"http://localhost:87632/.well-known/openid-credential-issuer\": dial tcp: address 87632: invalid port")
	})
}
