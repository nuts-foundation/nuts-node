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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	oauth2 "github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestWrapper_GetOpenID4VCIIssuerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		oidcIssuer.EXPECT().Metadata().Return(openid4vci.CredentialIssuerMetadata{
			CredentialIssuer: issuerDID.String(),
		})
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		response, err := api.GetOpenID4VCIIssuerMetadata(context.Background(), GetOpenID4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})

		require.NoError(t, err)
		assert.Equal(t, issuerDID.String(), response.(GetOpenID4VCIIssuerMetadata200JSONResponse).CredentialIssuer)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		api := Wrapper{VDR: vdr}

		_, err := api.GetOpenID4VCIIssuerMetadata(context.Background(), GetOpenID4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})

		require.EqualError(t, err, "invalid_request - DID is not owned by this node")
	})
}

func TestWrapper_GetOIDCProviderMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		oidcIssuer.EXPECT().ProviderMetadata().Return(openid4vci.ProviderMetadata{
			Issuer: issuerDID.String(),
		})
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		response, err := api.GetOIDCProviderMetadata(context.Background(), GetOIDCProviderMetadataRequestObject{Did: issuerDID.String()})

		require.NoError(t, err)
		assert.Equal(t, issuerDID.String(), response.(GetOIDCProviderMetadata200JSONResponse).Issuer)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		api := Wrapper{VDR: vdr}

		_, err := api.GetOIDCProviderMetadata(context.Background(), GetOIDCProviderMetadataRequestObject{Did: issuerDID.String()})

		require.EqualError(t, err, "invalid_request - DID is not owned by this node")
	})
}

func TestWrapper_RequestAccessToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		oidcIssuer.EXPECT().HandleAccessTokenRequest(gomock.Any(), "code").Return("access-token", "c_nonce", nil)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code", PreAuthorizedCode: "code",
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "access-token", response.(RequestAccessToken200JSONResponse).AccessToken)
		assert.Equal(t, "c_nonce", oauth2.TokenResponse(response.(RequestAccessToken200JSONResponse)).Get("c_nonce"))
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		api := Wrapper{VDR: vdr}

		_, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
		})

		require.EqualError(t, err, "invalid_request - DID is not owned by this node")
	})
	t.Run("unsupported grant type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "unsupported_grant_type - unsupported grant type: unsupported")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		require.Nil(t, response)
	})
}

func TestWrapper_RequestCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		oidcIssuer.EXPECT().HandleCredentialRequest(gomock.Any(), gomock.Any(), "access-token").Return(&vc.VerifiableCredential{}, nil)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		authz := "Bearer access-token"
		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: &authz,
			},
			Body: &RequestCredentialJSONRequestBody{
				Format:               "ldp_vc",
				CredentialDefinition: &openid4vci.CredentialDefinition{},
				Proof:                nil,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, response.(RequestCredential200JSONResponse).Credential)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		api := Wrapper{VDR: vdr}

		_, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
		})

		require.EqualError(t, err, "invalid_request - DID is not owned by this node")
	})
	t.Run("error - no authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: nil,
			},
			Body: nil,
		})

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_token - missing authorization header")
		assert.Equal(t, http.StatusUnauthorized, protocolError.StatusCode)
		assert.Nil(t, response)
	})
	t.Run("error - invalid authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOpenIDHandler(ctrl)
		documentOwner := didsubject.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		vdr := vdr.NewMockVDR(ctrl)
		vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOpenIDIssuer(gomock.Any(), issuerDID).Return(oidcIssuer, nil)
		api := Wrapper{VCR: service, VDR: vdr}

		authz := "invalid"
		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: &authz,
			},
			Body: nil,
		})

		var protocolError openid4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_token - invalid authorization header")
		assert.Equal(t, http.StatusUnauthorized, protocolError.StatusCode)
		assert.Nil(t, response)
	})
}
