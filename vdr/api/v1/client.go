/*
 * Nuts node
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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"io"
	"net/http"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	core.ClientConfig
	TokenGenerator core.AuthorizationTokenGenerator
}

func (hb HTTPClient) client() ClientInterface {
	response, err := NewClientWithResponses(hb.GetAddress(), WithHTTPClient(core.MustCreateInternalHTTPClient(hb.ClientConfig, hb.TokenGenerator)))
	if err != nil {
		panic(err)
	}
	return response
}

// Create calls the server and creates a new DID Document
func (hb HTTPClient) Create(createRequest DIDCreateRequest) (*did.Document, error) {
	ctx := context.Background()

	if response, err := hb.client().CreateDID(ctx, CreateDIDJSONRequestBody(createRequest)); err != nil {
		return nil, err
	} else if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
}

// Get returns a DID document and metadata based on a DID
func (hb HTTPClient) Get(DID string) (*DIDDocument, *DIDDocumentMetadata, error) {
	ctx := context.Background()

	response, err := hb.client().GetDID(ctx, DID, &GetDIDParams{})
	if err != nil {
		return nil, nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, nil, err
	}

	var resolutionResult *DIDResolutionResult
	if resolutionResult, err = readDIDResolutionResult(response.Body); err != nil {
		return nil, nil, err
	}
	return &resolutionResult.Document, &resolutionResult.DocumentMetadata, nil
}

// ConflictedDIDs returns the conflicted DID Documents and their metadata
func (hb HTTPClient) ConflictedDIDs() ([]DIDResolutionResult, error) {
	ctx := context.Background()

	response, err := hb.client().ConflictedDIDs(ctx)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	var resolutionResults []DIDResolutionResult
	if resolutionResults, err = readDIDResolutionResults(response.Body); err != nil {
		return nil, err
	}
	return resolutionResults, nil
}

// Update a DID Document given a DID and its current hash.
func (hb HTTPClient) Update(DID string, current string, next did.Document) (*did.Document, error) {
	ctx := context.Background()

	requestBody := UpdateDIDJSONRequestBody{
		Document:    next,
		CurrentHash: current,
	}
	response, err := hb.client().UpdateDID(ctx, DID, requestBody)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	return readDIDDocument(response.Body)
}

// Deactivate a DID Document given a DID.
// It expects a status 200 response from the server, returns an error otherwise.
func (hb HTTPClient) Deactivate(DID string) error {
	ctx := context.Background()
	response, err := hb.client().DeactivateDID(ctx, DID)
	if err != nil {
		return err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return err
	}
	return nil
}

// AddNewVerificationMethod creates a new verificationMethod and adds it to the DID document
// It expects a status 200 response from the server, returns an error otherwise
func (hb HTTPClient) AddNewVerificationMethod(DID string) (*did.VerificationMethod, error) {
	ctx := context.Background()

	response, err := hb.client().AddNewVerificationMethod(ctx, DID, AddNewVerificationMethodJSONRequestBody{})
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	return readVerificationMethod(response.Body)
}

// DeleteVerificationMethod deletes a specified verificationMethod from the DID document
// It expects a status 204 response from the server, returns an error otherwise
func (hb HTTPClient) DeleteVerificationMethod(DID, kid string) error {
	ctx := context.Background()

	response, err := hb.client().DeleteVerificationMethod(ctx, DID, kid)
	if err != nil {
		return err
	}
	return core.TestResponseCode(http.StatusNoContent, response)
}

func readDIDDocument(reader io.Reader) (*did.Document, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read DID Document response: %w", err)
	}
	document := did.Document{}
	if err = json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("unable to unmarshal DID Document response: %w, %s", err, string(data))
	}
	return &document, nil
}

func readDIDResolutionResult(reader io.Reader) (*DIDResolutionResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read DID Resolve response: %w", err)
	}
	resolutionResult := DIDResolutionResult{}
	if err = json.Unmarshal(data, &resolutionResult); err != nil {
		return nil, fmt.Errorf("unable to unmarshal DID Resolve response: %w", err)
	}
	return &resolutionResult, nil
}

func readDIDResolutionResults(reader io.Reader) ([]DIDResolutionResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	var resolutionResult []DIDResolutionResult
	if err = json.Unmarshal(data, &resolutionResult); err != nil {
		return nil, fmt.Errorf("unable to unmarshal []DIDResolutionResult response: %w", err)
	}
	return resolutionResult, nil
}

func readVerificationMethod(reader io.Reader) (*did.VerificationMethod, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read DID Resolve response: %w", err)
	}
	verificationMethod := did.VerificationMethod{}
	if err = json.Unmarshal(data, &verificationMethod); err != nil {
		return nil, fmt.Errorf("unable to unmarshal verification method response: %w, %s", err, string(data))
	}
	return &verificationMethod, nil
}
