package oidc4vci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"io"
	"net/http"
)

// IssuerClient defines the API client used by the wallet to communicate with the credential issuer.
type IssuerClient interface {
	OAuth2Client

	GetCredential(request types.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
}

// NewIssuerClient resolves the Credential Issuer Metadata from the well-known endpoint
// and returns a client that can be used to communicate with the issuer.
func NewIssuerClient(credentialIssuerIdentifier string) (IssuerClient, error) {
	if credentialIssuerIdentifier == "" {
		return nil, errors.New("empty Credential Issuer Identifier")
	}
	httpClient := http.Client{}

	// Load OIDC4VCI metadata and OIDC metadata
	metadata, err := loadCredentialIssuerMetadata(credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load Credential Issuer Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}
	providerMetadata, err := loadOIDCProviderMetadata(credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OIDC Provider Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}

	return &httpIssuerClient{
		httpOAuth2Client: httpOAuth2Client{
			httpClient: httpClient,
			metadata:   *providerMetadata,
		},
		identifier: credentialIssuerIdentifier,
		httpClient: httpClient,
		metadata:   *metadata,
	}, nil
}

var _ IssuerClient = (*httpIssuerClient)(nil)

type httpIssuerClient struct {
	httpOAuth2Client

	identifier       string
	httpClient       http.Client
	metadata         types.CredentialIssuerMetadata
	providerMetadata types.OIDCProviderMetadata
}

func (h httpIssuerClient) GetCredential(request types.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	requestBody, _ := json.Marshal(request)
	httpRequest, _ := http.NewRequest("POST", h.metadata.CredentialEndpoint, bytes.NewReader(requestBody))
	httpRequest.Header.Add("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Add("Content-Type", "application/json")
	httpResponse, err := h.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http response code: %d", httpResponse.StatusCode)
	}
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	var credentialResponse types.CredentialResponse
	err = json.Unmarshal(responseBody, &credentialResponse)
	if err != nil {
		return nil, fmt.Errorf("response unmarshal error: %w", err)
	}
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

func loadCredentialIssuerMetadata(credentialIssuerIdentifier string, httpClient http.Client) (*types.CredentialIssuerMetadata, error) {
	// TODO (non-prototype): Support HTTPS (which truststore?)
	// TODO (non-prototype): what about caching?
	httpResponse, err := httpClient.Get(credentialIssuerIdentifier + "/.well-known/openid-credential-issuer")
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	result := types.CredentialIssuerMetadata{}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	if len(result.CredentialEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain credential endpoint")
	}
	// TODO: Verify CredentialIssuer is the expected one
	return &result, nil
}

func loadOIDCProviderMetadata(credentialIssuerIdentifier string, httpClient http.Client) (*types.OIDCProviderMetadata, error) {
	//
	// Resolve OpenID Connect Provider Metadata, to find out where to request the token
	//
	// TODO (non-prototype): Support HTTPS (which truststore?)
	// TODO (non-prototype): what about caching?
	httpResponse, err := httpClient.Get(credentialIssuerIdentifier + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	result := types.OIDCProviderMetadata{}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	if len(result.TokenEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain token endpoint")
	}
	// TODO: Verify issuer is the expected one
	return &result, nil
}
