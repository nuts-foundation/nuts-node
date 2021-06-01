package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (h HTTPClient) client() ClientInterface {
	url := h.ServerAddress

	response, err := NewClientWithResponses(url)
	if err != nil {
		panic(err)
	}
	return response
}

// GetContactInformation retrieves the contact information registered on the given DID. If the DID does not exist,
// an error is returned. If the DID does exist but has no contact information nothing is returned.
func (h HTTPClient) GetContactInformation(did string) (*ContactInformation, error) {
	ctx, cancel := h.withTimeout()
	defer cancel()

	response, err := h.client().GetContactInformation(ctx, did)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusNotFound {
		// DID has no contact information
		return nil, nil
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	result, err := ParseGetContactInformationResponse(response)
	if err != nil {
		return nil, err
	}
	return result.JSON200, nil
}

// UpdateContactInformation (over)writes the contact information on given DID.
// If the DID does not exist an error is returned.
func (h HTTPClient) UpdateContactInformation(did string, information ContactInformation) error {
	ctx, cancel := h.withTimeout()
	defer cancel()

	response, err := h.client().UpdateContactInformation(ctx, did, UpdateContactInformationJSONRequestBody{
		Email:   information.Email,
		Name:    information.Name,
		Phone:   information.Phone,
		Website: information.Website,
	})
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusOK, response)
}

// AddEndpoint registers a concrete endpoint URL on the given DID.
func (h HTTPClient) AddEndpoint(did, endpointType, endpointURL string) error {
	ctx, cancel := h.withTimeout()
	defer cancel()
	response, err := h.client().AddEndpoint(ctx, did, AddEndpointJSONRequestBody{
		Type:     endpointType,
		Endpoint: endpointURL,
	})
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusNoContent, response)
}

// GetCompoundServices returns a list of compound services for a given DID string.
func (h HTTPClient) GetCompoundServices(did string) ([]CompoundService, error) {
	ctx, cancel := h.withTimeout()
	defer cancel()

	response, err := h.client().GetCompoundServices(ctx, did)
	if err != nil {
		return nil, err
	} else if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	return readCompoundServices(response.Body)
}

// AddCompoundService registers a compound service on the given DID.
func (h HTTPClient) AddCompoundService(did, serviceType string, references map[string]string) (*CompoundService, error) {
	ctx, cancel := h.withTimeout()
	defer cancel()
	refs := make(map[string]interface{}, 0)
	for k, v := range references {
		refs[k] = v
	}
	response, err := h.client().AddCompoundService(ctx, did, AddCompoundServiceJSONRequestBody{
		Type:            serviceType,
		ServiceEndpoint: refs,
	})
	if err != nil {
		return nil, err
	} else if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	return readCompoundService(response.Body)
}

func readCompoundServices(reader io.Reader) ([]CompoundService, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read compound services response: %w", err)
	}
	var cs []CompoundService
	if err = json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("unable to unmarshal compound servcice response: %w, %s", err, string(data))
	}
	return cs, nil
}

func readCompoundService(reader io.Reader) (*CompoundService, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read compound service response: %w", err)
	}
	cs := CompoundService{}
	if err = json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("unable to unmarshal compound servcice response: %w, %s", err, string(data))
	}
	return &cs, nil
}

// DeleteService tries to delete a service from the DID document indicated by the ID
// Returns an error if the service does not exists, is still in use or if the DID is not managed by this node.
func (h HTTPClient) DeleteService(id ssi.URI) error {
	ctx, cancel := h.withTimeout()
	defer cancel()
	response, err := h.client().DeleteService(ctx, id.String())
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusNoContent, response)
}

func (h HTTPClient) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.Timeout)
}
