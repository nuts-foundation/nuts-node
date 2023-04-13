package oidc4vci_v0

import (
	"github.com/nuts-foundation/go-did/did"
	"testing"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestWrapper_GetOIDC4VCIIssuerMetadata(t *testing.T) {
	//ctrl := gomock.NewController(t)
	//service := vcr.NewMockVCR(ctrl)
	//service.EXPECT().GetOIDCIssuer(issuerDID).Return()
	//api := Wrapper{VCR: service}
	//
	//response, err := api.GetOIDC4VCIIssuerMetadata(context.Background(), GetOIDC4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})
	//
	//require.NoError(t, err)
}

func TestWrapper_GetOIDCProviderMetadata(t *testing.T) {

}

func TestWrapper_RequestAccessToken(t *testing.T) {

}

func TestWrapper_RequestCredential(t *testing.T) {

}
