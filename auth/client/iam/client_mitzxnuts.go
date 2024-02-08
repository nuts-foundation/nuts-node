package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

func (hb HTTPClient) OpenIdConfiguration(ctx context.Context, serverURL url.URL) (*oauth.OpenIDConfigurationMetadata, error) {

	metadataURL, err := oauth.IssuerIdToWellKnown(serverURL.String(), oauth.OpenIdConfigurationWellKnown, hb.strictMode)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	var metadata oauth.OpenIDConfigurationMetadata
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return &metadata, nil
}

func (hb HTTPClient) OpenIdCredentialIssuerMetadata(ctx context.Context, webDID did.DID) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	serverURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, err
	}

	metadataURL, err := oauth.IssuerIdToWellKnown(serverURL.String(), oauth.OpenIdCredIssuerWellKnown, hb.strictMode)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	var metadata oauth.OpenIDCredentialIssuerMetadata
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return &metadata, nil
}

func (hb HTTPClient) AccessTokenOid4vci(ctx context.Context, clientId string, tokenEndpoint string, redirectUri string, code string, pkceCodeVerifier *string) (*oauth.Oid4vciTokenResponse, error) {
	presentationDefinitionURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return nil, err
	}
	// create a POST request with x-www-form-urlencoded body
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set("redirect_uri", redirectUri)
	if pkceCodeVerifier != nil {
		data.Set("code_verifier", *pkceCodeVerifier)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, presentationDefinitionURL.String(), strings.NewReader(data.Encode()))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		// check for oauth error
		if innerErr := core.TestResponseCode(http.StatusBadRequest, response); innerErr != nil {
			// a non oauth error, the response body could contain a lot of stuff. We'll log and return the entire error
			log.Logger().Debugf("authorization server token endpoint returned non oauth error (statusCode=%d)", response.StatusCode)
			return nil, err
		}
		httpErr := err.(core.HttpError)
		oauthError := oauth.OAuth2Error{}
		if err := json.Unmarshal(httpErr.ResponseBody, &oauthError); err != nil {
			return nil, fmt.Errorf("unable to unmarshal OAuth error response: %w", err)
		}

		return nil, oauthError
	}

	var responseData []byte
	if responseData, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}

	var token oauth.Oid4vciTokenResponse
	if err = json.Unmarshal(responseData, &token); err != nil {
		// Cut off the response body to 100 characters max to prevent logging of large responses
		responseBodyString := string(responseData)
		if len(responseBodyString) > 100 {
			responseBodyString = responseBodyString[:100] + "...(clipped)"
		}
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(responseData))
	}
	return &token, nil
}

type CredentialRequest struct {
	Proof CredentialRequestProof `json:"proof"`
}

type CredentialRequestProof struct {
	ProofType string `json:"proof_type"`
	Jwt       string `json:"jwt"`
}

type CredentialResponse struct {
	Format     string `json:"format"`
	Credential string `json:"credential"`
}

func (hb HTTPClient) VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJwt string) (*CredentialResponse, error) {

	credentialEndpointURL, err := url.Parse(credentialEndpoint)
	if err != nil {
		return nil, err
	}

	credentialRequest := CredentialRequest{
		Proof: CredentialRequestProof{
			ProofType: "jwt",
			Jwt:       proofJwt,
		},
	}
	jsonBody, err := json.Marshal(credentialRequest)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialEndpointURL.String(), bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+accessToken)

	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	defer response.Body.Close()
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	var credential CredentialResponse
	if err = json.NewDecoder(response.Body).Decode(&credential); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &credential, nil

}
