package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/nuts-node/core"
	"io"
	"net/http"
	"net/url"
)

// TODO: Split this file into multiple files, per role (issuer/holder)

type Wrapper struct {
}

func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, nil))
}

func (w Wrapper) GetOIDCProviderMeta(ctx context.Context, request GetOIDCProviderMetaRequestObject) (GetOIDCProviderMetaResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) GetOIDCIssuerMeta(ctx context.Context, request GetOIDCIssuerMetaRequestObject) (GetOIDCIssuerMetaResponseObject, error) {
	issuerDID := request.Did
	credentialEndp := "http://localhost:1323/identity/" + issuerDID + "/issuer/oidc4vci/credential"
	credentialIssuer := "http://localhost:1323/identity/" + issuerDID
	credentialsSupported := []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}}
	issuer := "http://localhost:1323/identity/" + issuerDID
	tokenEndp := "http://localhost:1323/identity/" + issuerDID + "/oidc/token"

	return GetOIDCIssuerMeta200JSONResponse(OIDCProviderMetadata{
		CredentialEndpoint:   &credentialEndp,
		CredentialIssuer:     &credentialIssuer,
		CredentialsSupported: &credentialsSupported,
		Issuer:               &issuer,
		TokenEndpoint:        &tokenEndp,
	}), nil
}

func (w Wrapper) CredentialOffer(ctx context.Context, request CredentialOfferRequestObject) (CredentialOfferResponseObject, error) {
	holderDID := request.Did
	offerParam, err := url.QueryUnescape(request.Params.CredentialOffer)
	if err != nil {
		return CredentialOffer400TextResponse("unable to unescape credential offer query param"), nil
	}
	offer := CredentialOffer{}
	if json.Unmarshal([]byte(offerParam), &offer) != nil {
		return CredentialOffer400TextResponse("unable to unmarshall credential offer query param"), nil
	}

	// TODO: store offer and perform these requests async

	c := http.Client{}
	metaDataResp, err := c.Get(offer.CredentialIssuer + "/.well-known/openid-credential-issuer")
	if err != nil {
		return CredentialOffer500TextResponse("unable to request meta data"), nil
	}
	body, _ := io.ReadAll(metaDataResp.Body)
	metaData := OIDCProviderMetadata{}
	if err := json.Unmarshal(body, &metaData); err != nil {
		return CredentialOffer500TextResponse("unable to unmarshall meta data"), nil
	}
	if metaData.TokenEndpoint == nil {
		return CredentialOffer500TextResponse("meta data does not contain token endpoint"), nil
	}

	tokenRequest := RequestAccessTokenFormdataBody{
		GrantType:         "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		PreAuthorizedCode: offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})["pre-authorized_code"].(string),
	}

	values, err := runtime.MarshalForm(&tokenRequest, nil)
	if err != nil {
		return CredentialOffer500TextResponse("unable to marshal token request"), nil
	}

	tokenResponse, err := c.PostForm(*metaData.TokenEndpoint, values)
	if err != nil {
		return CredentialOffer500TextResponse("unable to request token"), nil
	}

	if tokenResponse.StatusCode != http.StatusOK {
		return CredentialOffer500TextResponse("unable to request token, wrong status code"), nil
	}

	tokenResponseBody, _ := io.ReadAll(tokenResponse.Body)

	fmt.Printf("ReceiveCredentialOffer: %s, %v", holderDID, offer)
	fmt.Printf("tokenResponse: %v", tokenResponseBody)

	return CredentialOffer202TextResponse("OK"), nil
}

func (w Wrapper) GetCredential(ctx context.Context, request GetCredentialRequestObject) (GetCredentialResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	//TODO implement me
	panic("implement me")
}
