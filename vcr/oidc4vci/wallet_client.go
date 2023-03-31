package oidc4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"io"
	"net/http"
	"net/url"
)

var _ Wallet = (*httpWalletClient)(nil)

// NewWalletClient resolves the OAuth2 credential client metadata from the given URL.
func NewWalletClient(ctx context.Context, httpClient *http.Client, credentialClientMetadataURL string) (Wallet, error) {
	if credentialClientMetadataURL == "" {
		return nil, errors.New("empty credential client metadata URL")
	}

	metadata, err := loadOAuth2CredentialsClientMetadata(ctx, credentialClientMetadataURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OAuth2 credential client metadata (url=%s): %w", credentialClientMetadataURL, err)
	}

	return &httpWalletClient{
		httpClient: httpClient,
		metadata:   *metadata,
	}, nil
}

var _ Wallet = (*httpWalletClient)(nil)

type httpWalletClient struct {
	metadata   types.OAuth2ClientMetadata
	httpClient *http.Client
}

func (c *httpWalletClient) Metadata() types.OAuth2ClientMetadata {
	return c.metadata
}

func (c *httpWalletClient) OfferCredential(ctx context.Context, offer types.CredentialOffer) error {
	offerJson, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	requestURL := c.metadata.CredentialOfferEndpoint + "?credential_offer=" + url.QueryEscape(string(offerJson))

	httpRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, _ := io.ReadAll(httpResponse.Body)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		responseBodyStr := string(responseBody)
		// If longer than 100 characters, truncate
		if len(responseBodyStr) > 100 {
			responseBodyStr = responseBodyStr[:100] + "..."
		}
		log.Logger().Infof("Credential Offer response: %s", responseBodyStr)
		return fmt.Errorf("non 2xx status code: %s", httpResponse.Status)
	}
	return nil
}

func loadOAuth2CredentialsClientMetadata(ctx context.Context, metadataURL string, httpClient *http.Client) (*types.OAuth2ClientMetadata, error) {
	// TODO (non-prototype): Support HTTPS (which truststore?)
	// TODO (non-prototype): what about caching?
	httpRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	result := types.OAuth2ClientMetadata{}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	if len(result.CredentialOfferEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain credential offer endpoint")
	}
	// TODO: Verify client identifier is the expected one?
	return &result, nil
}
