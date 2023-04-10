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

func (w Wrapper) GetOIDC4VCIIssuerMetadata(_ context.Context, request GetOIDC4VCIIssuerMetadataRequestObject) (GetOIDC4VCIIssuerMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOIDC4VCIIssuerMetadata200JSONResponse(w.VCR.GetOIDCIssuer(*issuerDID).Metadata()), nil
}

func (w Wrapper) GetOIDCProviderMetadata(_ context.Context, request GetOIDCProviderMetadataRequestObject) (GetOIDCProviderMetadataResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOIDCProviderMetadata200JSONResponse(w.VCR.GetOIDCIssuer(*issuerDID).ProviderMetadata()), nil
}

func (w Wrapper) GetCredential(ctx context.Context, request GetCredentialRequestObject) (GetCredentialResponseObject, error) {
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
	return GetCredential200JSONResponse(CredentialResponse{
		Credential: &credentialMap,
		Format:     "VerifiableCredentialJSONLDFormat",
	}), nil
}

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
	expiresIn := 300
	cNonce := "nonsens"
	return RequestAccessToken200JSONResponse(TokenResponse{
		AccessToken: accessToken,
		CNonce:      &cNonce,
		ExpiresIn:   &expiresIn,
		TokenType:   "bearer",
	}), nil
}
