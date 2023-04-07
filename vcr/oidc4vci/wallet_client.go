package oidc4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

type Wallet interface {
	Metadata() OAuth2ClientMetadata
	OfferCredential(ctx context.Context, offer CredentialOffer) error
}

var _ Wallet = (*httpWalletClient)(nil)

// NewWalletClient resolves the OAuth2 credential client metadata from the given URL.
func NewWalletClient(ctx context.Context, httpClient *http.Client, walletMetadataURL string) (Wallet, error) {
	if walletMetadataURL == "" {
		return nil, errors.New("empty wallet metadata URL")
	}

	metadata, err := loadOAuth2CredentialsClientMetadata(ctx, walletMetadataURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OAuth2 credential client metadata (url=%s): %w", walletMetadataURL, err)
	}

	return &httpWalletClient{
		httpClient: httpClient,
		metadata:   *metadata,
	}, nil
}

var _ Wallet = (*httpWalletClient)(nil)

type httpWalletClient struct {
	metadata   OAuth2ClientMetadata
	httpClient *http.Client
}

func (c *httpWalletClient) Metadata() OAuth2ClientMetadata {
	return c.metadata
}

func (c *httpWalletClient) OfferCredential(ctx context.Context, offer CredentialOffer) error {
	offerJson, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	requestURL := c.metadata.CredentialOfferEndpoint + "?credential_offer=" + url.QueryEscape(string(offerJson))
	err = httpGet(ctx, c.httpClient, requestURL, nil)
	if err != nil {
		return fmt.Errorf("offer credential error: %w", err)
	}
	return err
}

func loadOAuth2CredentialsClientMetadata(ctx context.Context, metadataURL string, httpClient *http.Client) (*OAuth2ClientMetadata, error) {
	// TODO (non-prototype): Support HTTPS (which truststore?)
	// TODO (non-prototype): what about caching?
	result := OAuth2ClientMetadata{}
	err := httpGet(ctx, httpClient, metadataURL, &result)
	if err != nil {
		return nil, err
	}
	if len(result.CredentialOfferEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain credential offer endpoint")
	}
	// TODO: Verify client identifier is the expected one?
	return &result, nil
}
