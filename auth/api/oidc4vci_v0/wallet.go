package oidc4vci_v0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/types"
	"io"
	"net/http"
	"net/url"
)

func (w Wrapper) CredentialOffer(ctx context.Context, request CredentialOfferRequestObject) (CredentialOfferResponseObject, error) {
	holderDID := request.Did
	offerParam, err := url.QueryUnescape(request.Params.CredentialOffer)
	if err != nil {
		return CredentialOffer400TextResponse("unable to unescape credential offer query param"), nil
	}
	offer := types.CredentialOffer{}
	if json.Unmarshal([]byte(offerParam), &offer) != nil {
		return CredentialOffer400TextResponse("unable to unmarshall credential offer query param"), nil
	}

	// TODO (non-prototype): store offer and perform these requests async
	c := http.Client{}
	// TODO (non-prototype): Support HTTPS (which truststore?)
	//
	// Resolve OpenID Connect Provider Metadata, to find out where to request the token
	//
	// TODO (non-prototype): what about caching?
	providerMDResp, err := c.Get(offer.CredentialIssuer + "/.well-known/openid-configuration")
	defer providerMDResp.Body.Close()
	if err != nil {
		return CredentialOffer500TextResponse("unable to request meta data"), nil
	}
	body, _ := io.ReadAll(providerMDResp.Body)
	metaData := OIDCProviderMetadata{}
	if err := json.Unmarshal(body, &metaData); err != nil {
		return CredentialOffer500TextResponse("unable to unmarshall meta data"), nil
	}
	if metaData.TokenEndpoint == nil {
		return CredentialOffer500TextResponse("meta data does not contain token endpoint"), nil
	}

	//
	// Request the access token
	//
	tokenRequest := types.RequestAccessTokenFormdataBody{
		GrantType:         "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		PreAuthorizedCode: offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})["pre-authorized_code"].(string),
	}
	values, err := runtime.MarshalForm(&tokenRequest, nil)
	if err != nil {
		return CredentialOffer500TextResponse("unable to marshal token request"), nil
	}
	tokenResponse, err := c.PostForm(*metaData.TokenEndpoint, values)
	defer tokenResponse.Body.Close()
	if err != nil {
		return CredentialOffer500TextResponse("unable to request token"), nil
	}
	if tokenResponse.StatusCode != http.StatusOK {
		return CredentialOffer500TextResponse("unable to request token, wrong status code"), nil
	}
	tokenResponseBody, _ := io.ReadAll(tokenResponse.Body)
	accessTokenResponse := OIDCTokenResponse{}
	err = json.Unmarshal(tokenResponseBody, &accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal token response: %w", err)
	}
	fmt.Printf("CredentialOffer: %s, %v\n", holderDID, offer)

	// TODO (non-prototype): we now do this in a goroutine to avoid blocking the issuer's process
	go func() {
		credential, err := w.retrieveCredential(offer, metaData, accessTokenResponse.AccessToken)
		if err != nil {
			println("Unable to retrieve credential:", err.Error())
			return
		}
		// TODO (non-prototype): needs trying
		println("Received VC over OIDC4VCI, storing in VCR:", credential.ID.String())
		err = w.CredentialStore.StoreCredential(*credential, nil)
		if err != nil {
			println("Unable to store VC:", err.Error())
		}
	}()
	return CredentialOffer202TextResponse("OK"), nil
}

func (w Wrapper) retrieveCredential(offer types.CredentialOffer, metaData OIDCProviderMetadata, accessToken string) (*vc.VerifiableCredential, error) {
	//
	// Request the Verifiable Credential, using the access token as Authorization header
	//
	// TODO (non-prototype): now we re-use the resolved OIDC Provider Metadata,
	//                       but we should use resolve OIDC4VCI Credential Issuer Metadata and use its credential_endpoint instead
	println("Retrieving credential, access token:", accessToken)
	if metaData.CredentialEndpoint == nil {
		return nil, errors.New("issuer metadata does not contain credential_endpoint")
	}
	credentialRequest := types.CredentialRequest{
		// TODO (non-prototype): check there's credentials in the offer
		// TODO (non-prototype): support only 1 credential in the offer, or choose one (based on what?)
		CredentialDefinition: &offer.Credentials[0],
		// TODO (non-prototype): make this a constant?
		Format: "ldp_vc",
		// TODO (non-prototype): build actual proof
		Proof: &struct {
			Jwt       string `json:"jwt"`
			ProofType string `json:"proof_type"`
		}{
			Jwt:       "Trust me, I'm an engineer",
			ProofType: "jwt",
		},
	}
	credentialRequestJSON, _ := json.Marshal(credentialRequest)
	httpRequest, _ := http.NewRequest("POST", *metaData.CredentialEndpoint, bytes.NewReader(credentialRequestJSON))
	httpRequest.Header.Add("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Add("Content-Type", "application/json")
	httpResponse, err := (&http.Client{}).Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to request credential: %w", err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to request credential, wrong status code: %d", httpResponse.StatusCode)
	}
	credentialResponseJSON, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read credential response: %w", err)
	}
	var credentialResponse CredentialResponse
	err = json.Unmarshal(credentialResponseJSON, &credentialResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal credential response: %w", err)
	}
	//
	// Parse the Verifiable Credential and store it in VCR
	//
	// TODO (non-prototype): check format
	// TODO (non-prototype): process VC as JSON-LD?
	if credentialResponse.Credential == nil {
		return nil, errors.New("credential response does not contain a credential")
	}
	var credential vc.VerifiableCredential
	credentialJSON, _ := json.Marshal(*credentialResponse.Credential)
	err = json.Unmarshal(credentialJSON, &credential)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal received credential: %w", err)
	}
	return &credential, nil
}
