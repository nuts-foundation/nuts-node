package v1

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"time"
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

func (h HTTPClient) AddCompoundService(did, serviceType string, references map[string]string) error {
	ctx, cancel := h.withTimeout()
	defer cancel()
	refs := make(map[string]interface{}, 0)
	for k, v := range references {
		refs[k] = v
	}
	response, err := h.client().AddCompoundService(ctx, did, AddCompoundServiceJSONRequestBody{
		Type:     serviceType,
		Endpoint: refs,
	})
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusNoContent, response)
}

func (h HTTPClient) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.Timeout)
}
