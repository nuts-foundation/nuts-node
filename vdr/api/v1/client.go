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
	"io/ioutil"
	"net/http"
	"time"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HTTPClient) client() ClientInterface {
	url := hb.ServerAddress

	response, err := NewClientWithResponses(url)
	if err != nil {
		panic(err)
	}
	return response
}

// Create calls the server and creates a new DID Document
func (hb HTTPClient) Create() (*did.Document, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	if response, err := hb.client().CreateDID(ctx); err != nil {
		return nil, err
	} else if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
}

// Get returns a DID document and metadata based on a DID
func (hb HTTPClient) Get(DID string) (*DIDDocument, *DIDDocumentMetadata, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	response, err := hb.client().GetDID(ctx, DID)
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

// Update a DID Document given a DID and its current hash.
func (hb HTTPClient) Update(DID string, current string, next did.Document) (*did.Document, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

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
	ctx, cancel := hb.withTimeout()
	defer cancel()
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
// It expects a status 201 respond from the server, returns an error otherwise
func (hb HTTPClient) AddNewVerificationMethod(DID string) (*did.VerificationMethod, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	response, err := hb.client().AddNewVerificationMethod(ctx, DID)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusCreated, response); err != nil {
		return nil, err
	}

	return readVerificationMethod(response.Body)
}

func (hb HTTPClient) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), hb.Timeout)
}

func readDIDDocument(reader io.Reader) (*did.Document, error) {
	var data []byte
	var err error

	if data, err = ioutil.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read DID Document response: %w", err)
	}
	document := did.Document{}
	if err = json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("unable to unmarshal DID Document response: %w, %s", err, string(data))
	}
	return &document, nil
}

func readDIDResolutionResult(reader io.Reader) (*DIDResolutionResult, error) {
	var data []byte
	var err error

	if data, err = ioutil.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read DID Resolve response: %w", err)
	}
	resolutionResult := DIDResolutionResult{}
	if err = json.Unmarshal(data, &resolutionResult); err != nil {
		return nil, fmt.Errorf("unable to unmarshal DID Resolve response: %w", err)
	}
	return &resolutionResult, nil
}

func readVerificationMethod(reader io.Reader) (*did.VerificationMethod, error) {
	var data []byte
	var err error

	if data, err = ioutil.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read DID Resolve response: %w", err)
	}
	verificationMethod := did.VerificationMethod{}
	if err = json.Unmarshal(data, &verificationMethod); err != nil {
		return nil, fmt.Errorf("unable to unmarshal verification method response: %w, %s", err.Error(), string(data))
	}
	return &verificationMethod, nil
}
