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

package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
)

// WalletAPIClient defines a client interface for communicating with a remote wallet over OpenID4VCI.
type WalletAPIClient interface {
	// Metadata returns the OAuth2 client metadata of the remote wallet.
	Metadata() OAuth2ClientMetadata
	// OfferCredential sends a credential offer to the remote wallet.
	OfferCredential(ctx context.Context, offer CredentialOffer) error
}

var _ WalletAPIClient = (*defaultWalletAPIClient)(nil)

// NewWalletAPIClient resolves the OAuth2 credential client metadata from the given URL.
func NewWalletAPIClient(ctx context.Context, httpClient core.HTTPRequestDoer, walletMetadataURL string) (WalletAPIClient, error) {
	if walletMetadataURL == "" {
		return nil, errors.New("empty wallet metadata URL")
	}

	metadata, err := loadOAuth2CredentialsClientMetadata(ctx, walletMetadataURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OAuth2 credential client metadata (url=%s): %w", walletMetadataURL, err)
	}

	return &defaultWalletAPIClient{
		httpClient: httpClient,
		metadata:   *metadata,
	}, nil
}

var _ WalletAPIClient = (*defaultWalletAPIClient)(nil)

type defaultWalletAPIClient struct {
	metadata   OAuth2ClientMetadata
	httpClient core.HTTPRequestDoer
}

func (c *defaultWalletAPIClient) Metadata() OAuth2ClientMetadata {
	return c.metadata
}

func (c *defaultWalletAPIClient) OfferCredential(ctx context.Context, offer CredentialOffer) error {
	offerJson, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	requestURL := c.metadata.CredentialOfferEndpoint + "?credential_offer=" + url.QueryEscape(string(offerJson))
	response := CredentialOfferResponse{}
	err = httpGet(ctx, c.httpClient, requestURL, &response)
	if err != nil {
		return fmt.Errorf("offer credential error: %w", err)
	}
	if response.Status != CredentialOfferStatusReceived {
		return fmt.Errorf("offer credential error: unexpected status: %s", response.Status)
	}
	return nil
}

func loadOAuth2CredentialsClientMetadata(ctx context.Context, metadataURL string, httpClient core.HTTPRequestDoer) (*OAuth2ClientMetadata, error) {
	// TODO: what about caching?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2034
	result := OAuth2ClientMetadata{}
	err := httpGet(ctx, httpClient, metadataURL, &result)
	if err != nil {
		return nil, err
	}
	if len(result.CredentialOfferEndpoint) == 0 {
		return nil, errors.New("invalid meta data: does not contain credential offer endpoint")
	}
	return &result, nil
}
