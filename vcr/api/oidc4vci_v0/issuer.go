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

package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"strings"
)

// GetOIDC4VCIIssuerMetadata returns the OIDC4VCI credential issuer metadata for the given DID.
func (w Wrapper) GetOIDC4VCIIssuerMetadata(_ context.Context, request GetOIDC4VCIIssuerMetadataRequestObject) (GetOIDC4VCIIssuerMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOIDC4VCIIssuerMetadata200JSONResponse(w.VCR.GetOIDCIssuer(*issuerDID).Metadata()), nil
}

// GetOIDCProviderMetadata returns the OpenID Connect provider metadata for the given DID.
func (w Wrapper) GetOIDCProviderMetadata(_ context.Context, request GetOIDCProviderMetadataRequestObject) (GetOIDCProviderMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOIDCProviderMetadata200JSONResponse(w.VCR.GetOIDCIssuer(*issuerDID).ProviderMetadata()), nil
}

// RequestCredential requests a credential from the given DID.
func (w Wrapper) RequestCredential(ctx context.Context, request RequestCredentialRequestObject) (RequestCredentialResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	if request.Params.Authorization == nil {
		return nil, errors.New("missing authorization header")
	}
	authHeader := *request.Params.Authorization
	if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
		return nil, errors.New("invalid authorization header")
	}
	accessToken := authHeader[7:]
	credential, err := w.VCR.GetOIDCIssuer(*issuerDID).GetCredential(ctx, accessToken)
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
		Format:     "VerifiableCredentialJSONLDFormat",
	}), nil
}

// RequestAccessToken requests an OAuth2 access token from the given DID.
func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	if request.Body.GrantType != oidc4vci.PreAuthorizedCodeGrant {
		return nil, errors.New("unsupported grant type")
	}
	accessToken, err := w.VCR.GetOIDCIssuer(*issuerDID).RequestAccessToken(ctx, request.Body.PreAuthorizedCode)
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
