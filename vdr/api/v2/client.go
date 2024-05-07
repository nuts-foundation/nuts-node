/*
 * Nuts node
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

package v2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
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

// Create calls the server and creates a new DID Document
// It does not parse a custom id but depends on the server to generate one
func (hb HTTPClient) Create(options CreateDIDOptions) (*did.Document, error) {
	ctx := context.Background()

	if response, err := hb.client().CreateDID(ctx, options); err != nil {
		return nil, err
	} else if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
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
