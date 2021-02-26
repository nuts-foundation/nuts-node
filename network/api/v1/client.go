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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

// GetDocumentPayload retrieves the document payload for the given document. If the document or payload is not found
// nil is returned.
func (hb HTTPClient) GetDocumentPayload(documentRef hash.SHA256Hash) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().GetDocumentPayload(ctx, documentRef.String())
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := testResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	return ioutil.ReadAll(res.Body)
}

// GetDocument retrieves the document for the given reference. If the document is not known, an error is returned.
func (hb HTTPClient) GetDocument(documentRef hash.SHA256Hash) (dag.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().GetDocument(ctx, documentRef.String())
	if err != nil {
		return nil, err
	}
	return testAndParseDocumentResponse(res)
}

// ListDocuments returns all documents known to this network instance.
func (hb HTTPClient) ListDocuments() ([]dag.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().ListDocuments(ctx)
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	unparsedDocuments := make([]string, 0)
	if err = json.Unmarshal(responseData, &unparsedDocuments); err != nil {
		return nil, err
	}
	documents := make([]dag.Document, 0)
	for _, unparsedDocument := range unparsedDocuments {
		document, err := dag.ParseDocument([]byte(unparsedDocument))
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}

	return documents, nil
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

func testAndParseDocumentResponse(response *http.Response) (dag.Document, error) {
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return dag.ParseDocument(responseData)
}

func testResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("network returned HTTP %d (expected: %d), response: %s",
			response.StatusCode, expectedStatusCode, string(responseData))
	}
	return nil
}
