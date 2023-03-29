package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/types"
	"strings"
)

func (w Wrapper) GetOIDCIssuerMeta(ctx context.Context, request GetOIDCIssuerMetaRequestObject) (GetOIDCIssuerMetaResponseObject, error) {
	metadata := w.getOIDCIssuerMetadata(request.Did)
	return GetOIDCIssuerMeta200JSONResponse(metadata), nil
}

func (w Wrapper) GetCredential(ctx context.Context, request GetCredentialRequestObject) (GetCredentialResponseObject, error) {
	// TODO (non-prototype): Scope retrieving credential to issuer DID
	// TODO (non-prototype): Verify requested format
	// TODO (non-prototype): Verify Proof-of-Possession of private key material
	if request.Params.Authorization == nil {
		return nil, errors.New("missing authorization header")
	}
	authHeader := *request.Params.Authorization
	if len(authHeader) < 7 || strings.ToLower(authHeader[:7]) != "bearer " {
		return nil, errors.New("invalid authorization header")
	}
	accessToken := authHeader[7:]
	credential, err := w.Issuer.GetCredential(accessToken)
	if err != nil {
		return nil, err
	}
	// TODO (non-prototype): there could be checks here that must be performed, then an OAuth2 error with status "pending" should be returned
	format := "ldp_vc"
	credentialJSON, _ := credential.MarshalJSON()
	credentialMap := make(map[string]interface{})
	err = json.Unmarshal(credentialJSON, &credentialMap)
	if err != nil {
		return nil, err
	}
	return GetCredential200JSONResponse(CredentialResponse{
		Credential: &credentialMap,
		Format:     &format,
	}), nil
}

func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	if request.Body.GrantType != types.PreAuthorizedCodeGrant {
		return nil, errors.New("unsupported grant type")
	}
	accessToken, err := w.Issuer.RequestAccessToken(request.Body.PreAuthorizedCode)
	if err != nil {
		return nil, err
	}
	expiresIn := 300
	cNonce := "nonsens"
	return RequestAccessToken200JSONResponse(OIDCTokenResponse{
		AccessToken: accessToken,
		CNonce:      &cNonce,
		ExpiresIn:   &expiresIn,
		TokenType:   "bearer",
	}), nil
}

func (w Wrapper) getOIDCIssuerMetadata(issuerDID string) OIDCProviderMetadata {
	credentialEndp := "http://localhost:1323/identity/" + issuerDID + "/issuer/oidc4vci/credential"
	credentialIssuer := "http://localhost:1323/identity/" + issuerDID
	credentialsSupported := []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}}
	issuer := "http://localhost:1323/identity/" + issuerDID
	tokenEndp := "http://localhost:1323/identity/" + issuerDID + "/oidc/token"
	metadata := OIDCProviderMetadata{
		CredentialEndpoint:   &credentialEndp,
		CredentialIssuer:     &credentialIssuer,
		CredentialsSupported: &credentialsSupported,
		Issuer:               &issuer,
		TokenEndpoint:        &tokenEndp,
	}
	return metadata
}
