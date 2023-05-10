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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"net/http"
	"strings"
)

// GetOIDC4VCIIssuerMetadata returns the OIDC4VCI credential issuer metadata for the given DID.
func (w Wrapper) GetOIDC4VCIIssuerMetadata(_ context.Context, request GetOIDC4VCIIssuerMetadataRequestObject) (GetOIDC4VCIIssuerMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	metadata, err := w.VCR.GetOIDCIssuer().Metadata(*issuerDID)
	// Other error cases (will end up as 500)
	if err != nil {
		return nil, err
	}
	return GetOIDC4VCIIssuerMetadata200JSONResponse(metadata), nil
}

// GetOIDCProviderMetadata returns the OpenID Connect provider metadata for the given DID.
func (w Wrapper) GetOIDCProviderMetadata(_ context.Context, request GetOIDCProviderMetadataRequestObject) (GetOIDCProviderMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	metadata, err := w.VCR.GetOIDCIssuer().ProviderMetadata(*issuerDID)
	// Other error cases (will end up as 500)
	if err != nil {
		return nil, err
	}
	return GetOIDCProviderMetadata200JSONResponse(metadata), nil
}

// RequestCredential requests a credential from the given DID.
func (w Wrapper) RequestCredential(ctx context.Context, request RequestCredentialRequestObject) (RequestCredentialResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	if request.Params.Authorization == nil {
		return nil, oidc4vci.Error{
			Err:        errors.New("missing authorization header"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusUnauthorized,
		}
	}
	authHeader := *request.Params.Authorization
	if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
		return nil, oidc4vci.Error{
			Err:        errors.New("invalid authorization header"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusUnauthorized,
		}
	}
	accessToken := authHeader[7:]
	credentialRequest := *request.Body
	credential, err := w.VCR.GetOIDCIssuer().HandleCredentialRequest(ctx, *issuerDID, credentialRequest, accessToken)
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
		Format:     oidc4vci.VerifiableCredentialJSONLDFormat,
	}), nil
}

// RequestAccessToken requests an OAuth2 access token from the given DID.
func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	if request.Body.GrantType != oidc4vci.PreAuthorizedCodeGrant {
		return nil, oidc4vci.Error{
			Err:        fmt.Errorf("unsupported grant type: %s", request.Body.GrantType),
			Code:       oidc4vci.UnsupportedGrantType,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken, err := w.VCR.GetOIDCIssuer().HandleAccessTokenRequest(ctx, *issuerDID, request.Body.PreAuthorizedCode)
	if err != nil {
		return nil, err
	}
	// TODO: Revisit expires and nonce values
	//       See https://github.com/nuts-foundation/nuts-node/issues/2051
	expiresIn := 300
	cNonce := "nonsens"
	return RequestAccessToken200JSONResponse(TokenResponse{
		AccessToken: accessToken,
		CNonce:      &cNonce,
		ExpiresIn:   &expiresIn,
		TokenType:   "bearer",
	}), nil
}
