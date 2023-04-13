package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var holderDID = did.MustParseDID("did:nuts:holder")

func TestWrapper_GetOAuth2ClientMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	wallet := holder.NewMockOIDCWallet(ctrl)
	wallet.EXPECT().Metadata().Return(oidc4vci.OAuth2ClientMetadata{CredentialOfferEndpoint: "endpoint"})
	service := vcr.NewMockVCR(ctrl)
	service.EXPECT().GetOIDCWallet(holderDID).Return(wallet)
	api := Wrapper{VCR: service}

	response, err := api.GetOAuth2ClientMetadata(context.Background(), GetOAuth2ClientMetadataRequestObject{
		Did: holderDID.String(),
	})

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "endpoint", response.(GetOAuth2ClientMetadata200JSONResponse).CredentialOfferEndpoint)
}

func TestWrapper_HandleCredentialOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	wallet := holder.NewMockOIDCWallet(ctrl)
	wallet.EXPECT().HandleCredentialOffer(gomock.Any(), gomock.Any())
	service := vcr.NewMockVCR(ctrl)
	service.EXPECT().GetOIDCWallet(holderDID).Return(wallet)
	api := Wrapper{VCR: service}

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
	credentialOfferJSON, _ := json.Marshal(credentialOffer)

	response, err := api.HandleCredentialOffer(context.Background(), HandleCredentialOfferRequestObject{
		Did: holderDID.String(),
		Params: HandleCredentialOfferParams{
			CredentialOffer: string(credentialOfferJSON),
		},
	})

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "OK", string(response.(HandleCredentialOffer202TextResponse)))
}
