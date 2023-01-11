package storage

import (
	"context"
	"crypto"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/storage/httpclient"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"net/http"
)

// APIClient implements the Storage interface. It uses a simple HTTP protocol to connect to an external storage server.
// This server can either be a secret store itself, or proxy the request to a key store such as Hashicorp Vault or Azure Key Vault.
// It allows us to keep the codebase clean and allow other parties to write their own adaptor.
type APIClient struct {
	httpClient *httpclient.ClientWithResponses
}

func NewAPIClient(url string) *APIClient {
	client, _ := httpclient.NewClientWithResponses(url)

	return &APIClient{httpClient: client}
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
		return nil, fmt.Errorf("unable to get private-key: %w", err)
	}
	switch response.StatusCode() {
	case http.StatusOK:
		if contentType := response.HTTPResponse.Header.Get("Content-Type"); contentType != "application/json" {
			return nil, fmt.Errorf("unable to get private-key: unexpected content-type: %s", contentType)
		}

		privateKey, err := util.PemToPrivateKey([]byte(response.JSON200.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key as pem: %w", err)
		}
		return privateKey, nil
	case http.StatusNotFound:
		return nil, errKeyNotFound
	case http.StatusBadRequest:
		return nil, backendError{error: *response.JSON400}
	default:
		return nil, fmt.Errorf("unable to get private-key: unexpected status code from storage server: %d", response.StatusCode())
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
		return fmt.Errorf("unable to convert private key to pem format: %w", err)
	}
	response, err := c.httpClient.StoreSecretWithResponse(context.Background(), kid, httpclient.StoreSecretJSONRequestBody{Data: pem})
	if err != nil {
		return fmt.Errorf("unable to save private-key: %w", err)
	}
	switch response.StatusCode() {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		return backendError{error: *response.JSON400}
	case http.StatusConflict:
		return errKeyAlreadyExists
	default:
		return fmt.Errorf("unexpected status code from storage server: %d", response.StatusCode())
	}
}

func (c APIClient) ListPrivateKeys() []string {
	// not supported
	return []string{}
}
