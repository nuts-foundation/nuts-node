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

package external

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"net/http"
	"net/url"
	"time"
)

// StorageType is the name of this storage type, used in health check reports and configuration.
const StorageType = "external"

// APIClient implements the Storage interface. It uses a simple HTTP protocol to connect to an external storage server.
// This server can either be a secret store itself, or proxy the request to a key store such as Hashicorp Vault or Azure Key Vault.
// It allows us to keep the codebase clean and allow other parties to write their own adaptor.
type APIClient struct {
	httpClient *ClientWithResponses
}

func (c APIClient) Name() string {
	return "Crypto"
}

func (c APIClient) CheckHealth() map[string]core.Health {
	results := make(map[string]core.Health)
	response, err := c.httpClient.HealthCheckWithResponse(context.Background())
	if err != nil {
		results[StorageType] = core.Health{Status: core.HealthStatusDown, Details: fmt.Errorf("unable to connect to storage server: %w", err).Error()}
		return results
	}

	switch response.StatusCode() {
	case http.StatusOK:
		results[StorageType] = core.Health{Status: core.HealthStatusUp}
	case http.StatusServiceUnavailable:
		results[StorageType] = core.Health{Status: core.HealthStatusDown, Details: fmt.Sprintf("storage server reports to be unavailable: %d", response.StatusCode())}
	default:
		results[StorageType] = core.Health{Status: core.HealthStatusUnknown, Details: fmt.Sprintf("unexpected status code from storage server: %d", response.StatusCode())}
	}

	return results
}

// Config is the configuration for the APIClient.
type Config struct {
	// URL is the URL of the remote storage server.
	URL string `koanf:"url"`
	// Timeout is the timeout for the HTTP client.
	Timeout time.Duration `koanf:"timeout"`
}

// NewAPIClient create a new API Client to communicate with a remote storage server.
func NewAPIClient(u string, timeOut time.Duration) (spi.Storage, error) {
	if _, err := url.ParseRequestURI(u); err != nil {
		return nil, err
	}
	client, _ := NewClientWithResponses(u, WithHTTPClient(&http.Client{Timeout: timeOut}))
	return &APIClient{httpClient: client}, nil
}

func (c APIClient) GetPrivateKey(kid string) (crypto.Signer, error) {
	httpResponse, err := c.httpClient.LookupSecret(context.Background(), Key(kid))
	if err != nil {
		return nil, fmt.Errorf("unable to get private key: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, httpResponse); err != nil {
		if httpResponse.StatusCode == http.StatusNotFound {
			return nil, spi.ErrNotFound
		}
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}
	response, err := ParseLookupSecretResponse(httpResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}
	if response.JSON200 == nil {
		return nil, errors.New("invalid private key response from server")
	}
	privateKey, err := util.PemToPrivateKey([]byte(response.JSON200.Secret))
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key as PEM: %w", err)
	}
	return privateKey, nil
}

func (c APIClient) PrivateKeyExists(kid string) bool {
	response, err := c.httpClient.LookupSecretWithResponse(context.Background(), Key(kid))
	if err != nil {
		return false
	}
	return response.StatusCode() == http.StatusOK
}

func (c APIClient) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	pem, err := util.PrivateKeyToPem(key)
	if err != nil {
		return fmt.Errorf("unable to convert private key to PEM format: %w", err)
	}
	httpResponse, err := c.httpClient.StoreSecret(context.Background(), Key(kid), StoreSecretJSONRequestBody{Secret: pem})
	if err != nil {
		return fmt.Errorf("unable to save private key: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, httpResponse); err != nil {
		if httpResponse.StatusCode == http.StatusConflict {
			return spi.ErrKeyAlreadyExists
		}
		return fmt.Errorf("unable to save private key: %w", err)
	}
	_, _ = ParseStoreSecretResponse(httpResponse)
	return nil
}

func (c APIClient) ListPrivateKeys() []string {
	response, err := c.httpClient.ListKeysWithResponse(context.Background())
	if err != nil {
		return nil
	}
	switch response.StatusCode() {
	case http.StatusOK:
		if response.JSON200 == nil {
			return nil
		}
		keys := *response.JSON200
		result := make([]string, len(keys))
		for i, k := range keys {
			result[i] = string(k)
		}
		return result
	default:
		return nil
	}
}
