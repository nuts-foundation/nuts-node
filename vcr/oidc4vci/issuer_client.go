package oidc4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"io"
	"net/http"
)

// IssuerClient defines the API client used by the wallet to communicate with the credential issuer.
type IssuerClient interface {
	OAuth2Client

	Metadata() CredentialIssuerMetadata
	GetCredential(ctx context.Context, request CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
}

// NewIssuerClient resolves the Credential Issuer Metadata from the well-known endpoint
// and returns a client that can be used to communicate with the issuer.
func NewIssuerClient(ctx context.Context, httpClient *http.Client, credentialIssuerIdentifier string) (IssuerClient, error) {
	if credentialIssuerIdentifier == "" {
		return nil, errors.New("empty Credential Issuer Identifier")
	}

	// Load OIDC4VCI metadata and OIDC metadata
	metadata, err := loadCredentialIssuerMetadata(ctx, credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load Credential Issuer Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}
	providerMetadata, err := loadOIDCProviderMetadata(ctx, credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OIDC Provider Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}
	return NewIssuerClientFromMD(httpClient, *providerMetadata, *metadata)
}

// NewIssuerClientFromMD creates a new IssuerClient from preloaded metadata.
func NewIssuerClientFromMD(httpClient *http.Client, oidcProvider ProviderMetadata, credentialIssuer CredentialIssuerMetadata) (IssuerClient, error) {
	return &httpIssuerClient{
		httpOAuth2Client: httpOAuth2Client{
			httpClient: httpClient,
			metadata:   oidcProvider,
		},
		identifier: credentialIssuer.CredentialIssuer,
		httpClient: httpClient,
		metadata:   credentialIssuer,
	}, nil
}

var _ IssuerClient = (*httpIssuerClient)(nil)

type httpIssuerClient struct {
	httpOAuth2Client

	identifier       string
	httpClient       *http.Client
	metadata         CredentialIssuerMetadata
	providerMetadata ProviderMetadata
}

func (h httpIssuerClient) GetCredential(ctx context.Context, request CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	requestBody, _ := json.Marshal(request)

	var credentialResponse CredentialResponse
	httpRequest, _ := http.NewRequestWithContext(ctx, "POST", h.metadata.CredentialEndpoint, bytes.NewReader(requestBody))
	httpRequest.Header.Add("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Add("Content-Type", "application/json")
	err := httpDo(h.httpClient, httpRequest, &credentialResponse)
	if err != nil {
		return nil, fmt.Errorf("get credential request failed: %w", err)
	}
	// TODO: check format
	//       See https://github.com/nuts-foundation/nuts-node/issues/2037
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

func (h httpIssuerClient) Metadata() CredentialIssuerMetadata {
	return h.metadata
}

func loadCredentialIssuerMetadata(ctx context.Context, identifier string, httpClient *http.Client) (*CredentialIssuerMetadata, error) {
	// TODO: Support HTTPS (which truststore?)
	//       See https://github.com/nuts-foundation/nuts-node/issues/2032
	// TODO: what about caching?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2034
	result := CredentialIssuerMetadata{}
	err := httpGet(ctx, httpClient, identifier+CredentialIssuerMetadataWellKnownPath, &result)
	if err != nil {
		return nil, err
	}
	if len(result.CredentialEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain credential endpoint")
	}
	// TODO: Verify CredentialIssuer is the expected one
	//       See https://github.com/nuts-foundation/nuts-node/issues/2033
	return &result, nil
}

func loadOIDCProviderMetadata(ctx context.Context, identifier string, httpClient *http.Client) (*ProviderMetadata, error) {
	// TODO: Support HTTPS (which truststore?)
	//       See https://github.com/nuts-foundation/nuts-node/issues/2032
	// TODO: what about caching?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2034
	result := ProviderMetadata{}
	err := httpGet(ctx, httpClient, identifier+ProviderMetadataWellKnownPath, &result)
	if err != nil {
		return nil, err
	}
	if len(result.TokenEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain token endpoint")
	}
	// TODO: Verify issuer is the expected one
	//       See https://github.com/nuts-foundation/nuts-node/issues/2033
	return &result, nil
}

func httpGet(ctx context.Context, httpClient *http.Client, targetURL string, result interface{}) error {
	httpRequest, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	return httpDo(httpClient, httpRequest, result)
}

func httpDo(httpClient *http.Client, httpRequest *http.Request, result interface{}) error {
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("http request error (%s): %w", httpRequest.URL, err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("read error (%s): %w", httpRequest.URL, err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		responseBodyStr := string(responseBody)
		// If longer than 100 characters, truncate
		if len(responseBodyStr) > 100 {
			responseBodyStr = responseBodyStr[:100] + "..."
		}
		log.Logger().Debugf("HTTP response body: %s", responseBodyStr)
		return fmt.Errorf("unexpected http response code (%s): %d", httpRequest.URL, httpResponse.StatusCode)
	}
	if result != nil {
		if err := json.Unmarshal(responseBody, result); err != nil {
			return fmt.Errorf("%T JSON unmarshal error: %w", result, err)
		}
	}
	return nil
}
