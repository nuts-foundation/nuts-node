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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")

func TestWrapper_GetOIDC4VCIIssuerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().Metadata(issuerDID).Return(oidc4vci.CredentialIssuerMetadata{
			CredentialIssuer: issuerDID.String(),
		}, nil)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

		response, err := api.GetOIDC4VCIIssuerMetadata(context.Background(), GetOIDC4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})

		require.NoError(t, err)
		assert.Equal(t, issuerDID.String(), response.(GetOIDC4VCIIssuerMetadata200JSONResponse).CredentialIssuer)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.GetOIDC4VCIIssuerMetadata(context.Background(), GetOIDC4VCIIssuerMetadataRequestObject{Did: issuerDID.String()})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
}

func TestWrapper_GetOIDCProviderMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().ProviderMetadata(issuerDID).Return(oidc4vci.ProviderMetadata{
			Issuer: issuerDID.String(),
		}, nil)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

		response, err := api.GetOIDCProviderMetadata(context.Background(), GetOIDCProviderMetadataRequestObject{Did: issuerDID.String()})

		require.NoError(t, err)
		assert.Equal(t, issuerDID.String(), response.(GetOIDCProviderMetadata200JSONResponse).Issuer)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.GetOIDCProviderMetadata(context.Background(), GetOIDCProviderMetadataRequestObject{Did: issuerDID.String()})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
}

func TestWrapper_RequestAccessToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().HandleAccessTokenRequest(gomock.Any(), issuerDID, "code").Return("access-token", nil)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code", PreAuthorizedCode: "code",
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "access-token", response.(RequestAccessToken200JSONResponse).AccessToken)
	})
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
		})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
	t.Run("unsupported grant type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

		response, err := api.RequestAccessToken(context.Background(), RequestAccessTokenRequestObject{
			Did: issuerDID.String(),
			Body: &RequestAccessTokenFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		var protocolError oidc4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "unsupported_grant_type - unsupported grant type: unsupported")
		assert.Equal(t, http.StatusBadRequest, protocolError.StatusCode)
		require.Nil(t, response)
	})
}

func TestWrapper_RequestCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		oidcIssuer := issuer.NewMockOIDCIssuer(ctrl)
		oidcIssuer.EXPECT().HandleCredentialRequest(gomock.Any(), issuerDID, gomock.Any(), "access-token").Return(&vc.VerifiableCredential{}, nil)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().GetOIDCIssuer().Return(oidcIssuer)
		api := Wrapper{VCR: service, DocumentOwner: documentOwner}

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
	t.Run("unknown tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		_, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
		})

		require.EqualError(t, err, "invalid_request - holder or issuer not found")
	})
	t.Run("error - no authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: nil,
			},
			Body: nil,
		})

		var protocolError oidc4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_token - missing authorization header")
		assert.Equal(t, http.StatusUnauthorized, protocolError.StatusCode)
		assert.Nil(t, response)
	})
	t.Run("error - invalid authorization header", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)
		api := Wrapper{DocumentOwner: documentOwner}

		authz := "invalid"
		response, err := api.RequestCredential(context.Background(), RequestCredentialRequestObject{
			Did: issuerDID.String(),
			Params: RequestCredentialParams{
				Authorization: &authz,
			},
			Body: nil,
		})

		var protocolError oidc4vci.Error
		require.ErrorAs(t, err, &protocolError)
		assert.EqualError(t, protocolError, "invalid_token - invalid authorization header")
		assert.Equal(t, http.StatusUnauthorized, protocolError.StatusCode)
		assert.Nil(t, response)
	})
}
