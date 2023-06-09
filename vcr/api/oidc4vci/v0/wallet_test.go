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

package v0

import (
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var holderDID = did.MustParseDID("did:nuts:holder")

func TestWrapper_GetOAuth2ClientMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := holder.NewMockOIDCWallet(ctrl)
		wallet.EXPECT().Metadata().Return(oidc4vci.OAuth2ClientMetadata{CredentialOfferEndpoint: "endpoint"})
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCWallet(holderDID).Return(wallet)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

		response, err := api.GetOAuth2ClientMetadata(context.Background(), GetOAuth2ClientMetadataRequestObject{
			Did: holderDID.String(),
		})

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "endpoint", response.(GetOAuth2ClientMetadata200JSONResponse).CredentialOfferEndpoint)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.GetOAuth2ClientMetadata(context.Background(), GetOAuth2ClientMetadataRequestObject{
			Did: holderDID.String(),
		})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
}

func TestWrapper_HandleCredentialOffer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := holder.NewMockOIDCWallet(ctrl)
		wallet.EXPECT().HandleCredentialOffer(gomock.Any(), gomock.Any())
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCWallet(holderDID).Return(wallet)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

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
			Grants: map[string]interface{}{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
					"pre-authorized_code": "code",
				},
			},
		}
		credentialOfferJSON, _ := json.Marshal(credentialOffer)

		response, err := api.HandleCredentialOffer(context.Background(), HandleCredentialOfferRequestObject{
			Did: holderDID.String(),
			Params: HandleCredentialOfferParams{
				CredentialOffer: string(credentialOfferJSON),
			},
		})

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "credential_received", string(response.(HandleCredentialOffer200JSONResponse).Status))
	})

	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.HandleCredentialOffer(context.Background(), HandleCredentialOfferRequestObject{
			Did: holderDID.String(),
		})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
}
