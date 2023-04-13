package oidc4vci_v0

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestWrapper_GetOIDC4VCIIssuerMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
	oidcIssuer.EXPECT().Metadata(issuerDID).Return(oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer: issuerDID.String(),
	}, nil)
	service := vcr.NewMockVCR(ctrl)
	service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
	api := Wrapper{VCR: service}

	response, err := api.GetOIDC4VCIIssuerMetadata(context.Background(), GetOIDC4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})

	require.NoError(t, err)
	assert.Equal(t, issuerDID.String(), response.(GetOIDC4VCIIssuerMetadata200JSONResponse).CredentialIssuer)
}

func TestWrapper_GetOIDCProviderMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
	oidcIssuer.EXPECT().ProviderMetadata(issuerDID).Return(oidc4vci.ProviderMetadata{
		Issuer: issuerDID.String(),
	}, nil)
	service := vcr.NewMockVCR(ctrl)
	service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
	api := Wrapper{VCR: service}

	response, err := api.GetOIDCProviderMetadata(context.Background(), GetOIDCProviderMetadataRequestObject{Did: issuerDID.String()})

	require.NoError(t, err)
	assert.Equal(t, issuerDID.String(), response.(GetOIDCProviderMetadata200JSONResponse).Issuer)
}

func TestWrapper_RequestAccessToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().RequestAccessToken(gomock.Any(), issuerDID, "code").Return("access-token", nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code", PreAuthorizedCode: "code",
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "access-token", response.(RequestAccessToken200JSONResponse).AccessToken)
	})
	t.Run("unsupported grant type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		service := vcr.NewMockVCR(ctrl)
		api := Wrapper{VCR: service}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		require.EqualError(t, err, "unsupported grant type")
		require.Nil(t, response)
	})
}

func TestWrapper_RequestCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().HandleCredentialRequest(gomock.Any(), issuerDID, "access-token").Return(&vc.VerifiableCredential{}, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service}

		authz := "Bearer access-token"
		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: &authz,
			},
			Body: &RequestCredentialJSONRequestBody{
				Format:               "ldp_vc",
				CredentialDefinition: &map[string]interface{}{},
				Proof:                nil,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, response.(RequestCredential200JSONResponse).Credential)
	})
	t.Run("error - no authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		service := vcr.NewMockVCR(ctrl)
		api := Wrapper{VCR: service}

		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: nil,
			},
			Body: nil,
		})

		require.EqualError(t, err, "missing authorization header")
		assert.Nil(t, response)
	})
	t.Run("error - invalid authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		service := vcr.NewMockVCR(ctrl)
		api := Wrapper{VCR: service}

		authz := "invalid"
		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: &authz,
			},
			Body: nil,
		})

		require.EqualError(t, err, "invalid authorization header")
		assert.Nil(t, response)
	})
}
