/*
 * Copyright (C) 2021 Nuts community
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

package v1

import (
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	core.ClientConfig
	TokenGenerator core.AuthorizationTokenGenerator
}

func (hb HTTPClient) client() ClientInterface {
	response, err := NewClientWithResponses(hb.GetAddress(), WithHTTPClient(core.MustCreateHTTPClient(hb.ClientConfig, hb.TokenGenerator)))
	if err != nil {
		panic(err)
	}
	return response
}

// GetContactInformation retrieves the contact information registered on the given DID. If the DID does not exist,
// an error is returned. If the DID does exist but has no contact information nothing is returned.
func (hb HTTPClient) GetContactInformation(did string) (*ContactInformation, error) {
	ctx := context.Background()

	response, err := hb.client().GetContactInformation(ctx, did)
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
func (hb HTTPClient) UpdateContactInformation(did string, information ContactInformation) error {
	ctx := context.Background()

	response, err := hb.client().UpdateContactInformation(ctx, did, UpdateContactInformationJSONRequestBody{
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
func (hb HTTPClient) AddEndpoint(did, endpointType, endpointURL string) (*Endpoint, error) {
	ctx := context.Background()

	response, err := hb.client().AddEndpoint(ctx, did, AddEndpointJSONRequestBody{
		Type:     endpointType,
		Endpoint: endpointURL,
	})
	if err != nil {
		return nil, err
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	parsedResponse, err := ParseAddEndpointResponse(response)
	if err != nil {
		return nil, err
	}
	return parsedResponse.JSON200, nil
}

// DeleteEndpointsByType deletes an endpoint by type on a DID document indicated by the did.
func (hb HTTPClient) DeleteEndpointsByType(did, endpointType string) error {
	ctx := context.Background()

	response, err := hb.client().DeleteEndpointsByType(ctx, did, endpointType)
	if err != nil {
		return err
	}
	if err = core.TestResponseCode(http.StatusNoContent, response); err != nil {
		return err
	}
	return nil
}

// GetCompoundServices returns a list of compound services for a given DID string.
func (hb HTTPClient) GetCompoundServices(did string) ([]CompoundService, error) {
	ctx := context.Background()

	response, err := hb.client().GetCompoundServices(ctx, did)
	if err != nil {
		return nil, err
	} else if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	parsedResponse, err := ParseGetCompoundServicesResponse(response)
	if err != nil {
		return nil, err
	}
	return *parsedResponse.JSON200, nil
}

// AddCompoundService registers a compound service on the given DID.
func (hb HTTPClient) AddCompoundService(did, serviceType string, references map[string]string) (*CompoundService, error) {
	ctx := context.Background()
	refs := make(map[string]interface{}, 0)
	for k, v := range references {
		refs[k] = v
	}
	response, err := hb.client().AddCompoundService(ctx, did, AddCompoundServiceJSONRequestBody{
		Type:            serviceType,
		ServiceEndpoint: refs,
	})
	if err != nil {
		return nil, err
	} else if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	parsedResponse, err := ParseAddCompoundServiceResponse(response)
	if err != nil {
		return nil, err
	}
	return parsedResponse.JSON200, err
}

// DeleteService tries to delete a service from the DID document indicated by the ID
// Returns an error if the service does not exists, is still in use or if the DID is not managed by this node.
func (hb HTTPClient) DeleteService(id ssi.URI) error {
	ctx := context.Background()

	response, err := hb.client().DeleteService(ctx, id.String())
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusNoContent, response)
}
