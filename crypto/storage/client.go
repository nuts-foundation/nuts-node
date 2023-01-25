package storage

import (
	"context"
	"crypto"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/storage/httpclient"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"net/http"
	"net/url"
	"time"
)

const StorageAPIConfigKey = "external-store"
const httpClientTimeout = 100 * time.Millisecond

// APIClient implements the Storage interface. It uses a simple HTTP protocol to connect to an external storage server.
// This server can either be a secret store itself, or proxy the request to a key store such as Hashicorp Vault or Azure Key Vault.
// It allows us to keep the codebase clean and allow other parties to write their own adaptor.
type APIClient struct {
	httpClient *httpclient.ClientWithResponses
}

func (c APIClient) Name() string {
	return "Crypto"
}

func (c APIClient) CheckHealth() map[string]core.Health {
	results := make(map[string]core.Health)
	response, err := c.httpClient.HealthCheckWithResponse(context.Background())
	if err != nil {
		results[StorageAPIConfigKey] = core.Health{Status: core.HealthStatusDown, Details: fmt.Errorf("unable to connect to storage server: %w", err).Error()}
		return results
	}

	switch response.StatusCode() {
	case http.StatusOK:
		results[StorageAPIConfigKey] = core.Health{Status: core.HealthStatusUp}
	case http.StatusServiceUnavailable:
		results[StorageAPIConfigKey] = core.Health{Status: core.HealthStatusDown, Details: fmt.Sprintf("storage server reports to be unavailable: %d", response.StatusCode())}
	default:
		results[StorageAPIConfigKey] = core.Health{Status: core.HealthStatusUnknown, Details: fmt.Sprintf("unexpected status code from storage server: %d", response.StatusCode())}
	}

	return results
}

type APIClientConfig struct {
	URL string `koanf:"url"`
}

// NewAPIClient create a new API Client to communicate with a remote storage server.
func NewAPIClient(u string) (Storage, error) {
	if _, err := url.ParseRequestURI(u); err != nil {
		return nil, err
	}
	client, _ := httpclient.NewClientWithResponses(u, httpclient.WithHTTPClient(&http.Client{Timeout: httpClientTimeout}))
	return &APIClient{httpClient: client}, nil
}

type backendError struct {
	error httpclient.ErrorResponse
}

func (r backendError) Error() string {
	return fmt.Sprintf("remote error: the backend %s returned an error with status %d, title=%s details=%s", r.error.Backend, r.error.Status, r.error.Title, r.error.Detail)
}

func (c APIClient) GetPrivateKey(kid string) (crypto.Signer, error) {
	response, err := c.httpClient.LookupSecretWithResponse(context.Background(), kid)
	if err != nil {
		return nil, fmt.Errorf("unable to get private key: %w", err)
	}
	switch response.StatusCode() {
	case http.StatusOK:
		if response.JSON200 == nil {
			return nil, fmt.Errorf("unable to get private key: no body or wrong content-type")
		}

		privateKey, err := util.PemToPrivateKey([]byte(response.JSON200.Secret))
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key as PEM: %w", err)
		}
		return privateKey, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusBadRequest:
		if response.JSON400 != nil {
			return nil, backendError{error: *response.JSON400}
		}
		// not able to parse the error response, log it and fall through to default
		log.Logger().Errorf("unable to get private key: server responded with bad-request and malformed error response.")
		fallthrough
	default:
		return nil, fmt.Errorf("unable to get private key: unexpected status code from storage server: %d", response.StatusCode())
	}
}

func (c APIClient) PrivateKeyExists(kid string) bool {
	response, err := c.httpClient.LookupSecretWithResponse(context.Background(), kid)
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
	response, err := c.httpClient.StoreSecretWithResponse(context.Background(), kid, httpclient.StoreSecretJSONRequestBody{Secret: pem})
	if err != nil {
		return fmt.Errorf("unable to save private key: %w", err)
	}
	switch response.StatusCode() {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return ErrKeyAlreadyExists
	case http.StatusBadRequest:
		if response.JSON400 != nil {
			return backendError{error: *response.JSON400}
		}
		// not able to parse the error response, log it and fall through to default
		log.Logger().Errorf("unable to save private key: server responded with bad-request and malformed error response.")
		fallthrough
	default:
		return fmt.Errorf("unable to save private key: unexpected status code from storage server: %d", response.StatusCode())
	}
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
		return *response.JSON200
	default:
		return nil
	}
}
