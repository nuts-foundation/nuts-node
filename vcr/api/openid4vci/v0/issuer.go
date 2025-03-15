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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"net/http"
	"strings"
)

func (w Wrapper) getIssuerHandler(ctx context.Context, issuer string) (issuer.OpenIDHandler, error) {
	issuerDID, err := w.validateDIDIsOwned(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return w.VCR.GetOpenIDIssuer(ctx, issuerDID)
}

// GetOpenID4VCIIssuerMetadata returns the OpenID4VCI credential issuer metadata for the given DID.
func (w Wrapper) GetOpenID4VCIIssuerMetadata(ctx context.Context, request GetOpenID4VCIIssuerMetadataRequestObject) (GetOpenID4VCIIssuerMetadataResponseObject, error) {
	issuer, err := w.getIssuerHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	return GetOpenID4VCIIssuerMetadata200JSONResponse(issuer.Metadata()), nil
}

// GetOpenID4VCIIssuerMetadataHeaders returns the OpenID4VCI credential issuer metadata headers for the given DID.
func (w Wrapper) GetOpenID4VCIIssuerMetadataHeaders(ctx context.Context, request GetOpenID4VCIIssuerMetadataHeadersRequestObject) (GetOpenID4VCIIssuerMetadataHeadersResponseObject, error) {
	response := GetOpenID4VCIIssuerMetadataHeadersdefaultResponse{
		Headers: GetOpenID4VCIIssuerMetadataHeadersdefaultResponseHeaders{
			ContentType: "application/json",
		},
	}
	_, err := w.validateDIDIsOwned(ctx, request.Did)
	if err != nil {
		response.StatusCode = http.StatusNotFound
	} else {
		response.StatusCode = http.StatusOK
	}
	return response, nil
}

// GetOIDCProviderMetadata returns the OpenID Connect provider metadata for the given DID.
func (w Wrapper) GetOIDCProviderMetadata(ctx context.Context, request GetOIDCProviderMetadataRequestObject) (GetOIDCProviderMetadataResponseObject, error) {
	issuer, err := w.getIssuerHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	return GetOIDCProviderMetadata200JSONResponse(issuer.ProviderMetadata()), nil
}

// RequestCredential requests a credential from the given DID.
func (w Wrapper) RequestCredential(ctx context.Context, request RequestCredentialRequestObject) (RequestCredentialResponseObject, error) {
	issuer, err := w.getIssuerHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	if request.Params.Authorization == nil {
		return nil, openid4vci.Error{
			Err:        errors.New("missing authorization header"),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusUnauthorized,
		}
	}
	authHeader := *request.Params.Authorization
	if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
		return nil, openid4vci.Error{
			Err:        errors.New("invalid authorization header"),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusUnauthorized,
		}
	}
	accessToken := authHeader[7:]
	credentialRequest := *request.Body
	credential, err := issuer.HandleCredentialRequest(ctx, credentialRequest, accessToken)
	if err != nil {
		return nil, err
	}
	credentialJSON, _ := credential.MarshalJSON()
	credentialMap := make(map[string]interface{})
	err = json.Unmarshal(credentialJSON, &credentialMap)
	if err != nil {
		return nil, err
	}
	return RequestCredential200JSONResponse(CredentialResponse{
		Credential: &credentialMap,
		Format:     vc.JSONLDCredentialProofFormat,
	}), nil
}

// RequestAccessToken requests an OAuth2 access token from the given DID.
func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	issuerHandler, err := w.getIssuerHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	if request.Body.GrantType != openid4vci.PreAuthorizedCodeGrant {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("unsupported grant type: %s", request.Body.GrantType),
			Code:       openid4vci.UnsupportedGrantType,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken, cNonce, err := issuerHandler.HandleAccessTokenRequest(ctx, request.Body.PreAuthorizedCode)
	if err != nil {
		return nil, err
	}
	expiresIn := int(issuer.TokenTTL.Seconds())
	return RequestAccessToken200JSONResponse(*(&TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   &expiresIn,
		TokenType:   "bearer",
	}).With(oauth.CNonceParam, cNonce)), nil
}
