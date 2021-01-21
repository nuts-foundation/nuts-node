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
	"io"

	"github.com/nuts-foundation/go-did"

	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HTTPClient) client() ClientInterface {
	url := hb.ServerAddress
	if !strings.Contains(url, "http") {
		url = fmt.Sprintf("http://%v", hb.ServerAddress)
	}

	response, err := NewClientWithResponses(url)
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HTTPClient) Create() (*did.Document, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	if response, err := hb.client().CreateDID(ctx); err != nil {
		return nil, err
	} else if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
}

func (hb HTTPClient) Get(DID string) (*DIDDocument, *DIDDocumentMetadata, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	response, err := hb.client().GetDID(ctx, DID)
	if err != nil {
		return nil, nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, nil, err
	}

	if resolutionResult, err := readDIDResolutionResult(response.Body); err != nil {
		return nil, nil, err
	} else {
		return &resolutionResult.Document, &resolutionResult.DocumentMetadata, nil
	}
}

func (hb HTTPClient) Update(DID string, current string, next did.Document) (*did.Document, error) {
	ctx, cancel := hb.withTimeout()
	defer cancel()

	requestBody := UpdateDIDJSONRequestBody{
		Document: next,
		CurrentHash: current,
	}
	response, err := hb.client().UpdateDID(ctx, DID, requestBody)
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
}

func (hb HTTPClient) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), hb.Timeout)
}

func testResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("registry returned HTTP %d (expected: %d), response: %s",
			response.StatusCode, expectedStatusCode, string(responseData))
	}
	return nil
}

func readDIDDocument(reader io.Reader) (*did.Document, error) {
	if data, err := ioutil.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read DID Document response: %w", err)
	} else {
		document := did.Document{}
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, fmt.Errorf("unable to unmarshal DID Document response: %w, %s", err, string(data))
		}
		return &document, nil
	}
}

func readDIDResolutionResult(reader io.Reader) (*DIDResolutionResult, error) {
	if data, err := ioutil.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read DID Resolve response: %w", err)
	} else {
		resolutionResult := DIDResolutionResult{}
		if err := json.Unmarshal(data, &resolutionResult); err != nil {
			return nil, fmt.Errorf("unable to unmarshal DID Resolve response: %w", err)
		}
		return &resolutionResult, nil
	}
}
