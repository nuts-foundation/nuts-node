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

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	strictMode bool
	httpClient core.HTTPRequestDoer
}

// OAuthAuthorizationServerMetadata retrieves the OAuth authorization server metadata for the given web DID.
func (hb HTTPClient) OAuthAuthorizationServerMetadata(ctx context.Context, webDID did.DID) (*oauth.AuthorizationServerMetadata, error) {
	serverURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, err
	}

	metadataURL, err := oauth.IssuerIdToWellKnown(serverURL.String(), oauth.AuthzServerWellKnown, hb.strictMode)
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

	var metadata oauth.AuthorizationServerMetadata
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return &metadata, nil
}

// ClientMetadata retrieves the client metadata from the client metadata endpoint given in the authorization request.
// We use the AuthorizationServerMetadata struct since it overlaps greatly with the client metadata.
func (hb HTTPClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	_, err := core.ParsePublicURL(endpoint, hb.strictMode)
	if err != nil {
		return nil, err
	}

	// create a GET request
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	var metadata oauth.OAuthClientMetadata
	return &metadata, hb.doRequest(ctx, request, &metadata)
}

// PresentationDefinition retrieves the presentation definition from the presentation definition endpoint (as specified by RFC021) for the given scope.
func (hb HTTPClient) PresentationDefinition(ctx context.Context, presentationDefinitionURL url.URL) (*pe.PresentationDefinition, error) {
	// create a GET request with scope query param
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, presentationDefinitionURL.String(), nil)
	if err != nil {
		return nil, err
	}
	var presentationDefinition pe.PresentationDefinition
	return &presentationDefinition, hb.doRequest(ctx, request, &presentationDefinition)
}

func (hb HTTPClient) AccessToken(ctx context.Context, tokenEndpoint string, data url.Values, dpopHeader string) (oauth.TokenResponse, error) {
	var token oauth.TokenResponse
	tokenURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return token, err
	}

	// create a POST request with x-www-form-urlencoded body
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(data.Encode()))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if dpopHeader != "" {
		request.Header.Add("DPoP", dpopHeader)
	}
	if err != nil {
		return token, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return token, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		// check for oauth error
		if innerErr := core.TestResponseCode(http.StatusBadRequest, response); innerErr != nil {
			// a non oauth error, the response body could contain a lot of stuff. We'll log and return the entire error
			log.Logger().Debugf("authorization server token endpoint returned non oauth error (statusCode=%d)", response.StatusCode)
			return token, err
		}
		httpErr := err.(core.HttpError)
		oauthError := oauth.OAuth2Error{}
		if err := json.Unmarshal(httpErr.ResponseBody, &oauthError); err != nil {
			return token, fmt.Errorf("unable to unmarshal OAuth error response: %w", err)
		}

		return token, oauthError
	}

	var responseData []byte
	if responseData, err = io.ReadAll(response.Body); err != nil {
		return token, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(responseData, &token); err != nil {
		// Cut off the response body to 100 characters max to prevent logging of large responses
		responseBodyString := string(responseData)
		if len(responseBodyString) > core.HttpResponseBodyLogClipAt {
			responseBodyString = responseBodyString[:core.HttpResponseBodyLogClipAt] + "...(clipped)"
		}
		return token, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(responseData))
	}
	return token, nil
}

// PostError posts an OAuth error to the redirect URL and returns the redirect URL with the error as query parameter.
func (hb HTTPClient) PostError(ctx context.Context, err oauth.OAuth2Error, verifierCallbackURL url.URL) (string, error) {
	// initiate http client, create a POST request with x-www-form-urlencoded body and send it to the redirect URL
	data := url.Values{}
	data.Set(oauth.ErrorParam, string(err.Code))
	data.Set(oauth.ErrorDescriptionParam, err.Description)

	return hb.postFormExpectRedirect(ctx, data, verifierCallbackURL)
}

// PostAuthorizationResponse posts the authorization response to the verifier response URL and returns the callback URL.
func (hb HTTPClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI url.URL, state string) (string, error) {
	// initiate http client, create a POST request with x-www-form-urlencoded body and send it to the redirect URL
	psBytes, _ := json.Marshal(presentationSubmission)
	data := url.Values{}
	data.Set(oauth.VpTokenParam, vp.Raw())
	data.Set(oauth.PresentationSubmissionParam, string(psBytes))
	data.Set(oauth.StateParam, state)

	return hb.postFormExpectRedirect(ctx, data, verifierResponseURI)
}

func (hb HTTPClient) OpenIdConfiguration(ctx context.Context, serverURL string) (*oauth.OpenIDConfigurationMetadata, error) {

	metadataURL, err := oauth.IssuerIdToWellKnown(serverURL, oauth.OpenIdConfigurationWellKnown, hb.strictMode)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
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
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
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

func (hb HTTPClient) AccessTokenOid4vci(ctx context.Context, presentationDefinitionURL url.URL, data url.Values) (*oauth.Oid4vciTokenResponse, error) {
	// create a POST request with x-www-form-urlencoded body
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

// CredentialRequest represents ths request to fetch a credential, the JSON object holds the proof as
// CredentialRequestProof.
type CredentialRequest struct {
	Proof CredentialRequestProof `json:"proof"`
}

// CredentialRequestProof holds the ProofType and Jwt for a credential request
type CredentialRequestProof struct {
	ProofType string `json:"proof_type"`
	Jwt       string `json:"jwt"`
}

// CredentialResponse represents the response of a verifiable credential request.
// It contains the Format and the actual Credential in JSON format.
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Logger().WithError(err).Warn("Trouble closing reader")
		}
	}(response.Body)
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	var credential CredentialResponse
	if err = json.NewDecoder(response.Body).Decode(&credential); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &credential, nil

}
func (hb HTTPClient) postFormExpectRedirect(ctx context.Context, form url.Values, redirectURL url.URL) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, redirectURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	var redirect oauth.Redirect
	if err := hb.doRequest(ctx, request, &redirect); err != nil {
		return "", err
	}
	return redirect.RedirectURI, nil
}

func (hb HTTPClient) doRequest(ctx context.Context, request *http.Request, target interface{}) error {
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to call endpoint: %w", err)
	}
	if httpErr := core.TestResponseCode(http.StatusOK, response); httpErr != nil {
		rse := httpErr.(core.HttpError)
		if ok, oauthErr := oauth.TestOAuthErrorCode(rse.ResponseBody, oauth.InvalidScope); ok {
			return oauthErr
		}
		return httpErr
	}

	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &target); err != nil {
		return fmt.Errorf("unable to unmarshal response: %w", err)
	}

	return nil
}
