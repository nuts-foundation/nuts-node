/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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

// HttpClient holds the server address and other basic settings for the http client
type HttpClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HttpClient) client() ClientInterface {
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

func (hb HttpClient) Search(onlyOwn bool, tags []string) ([]did.Document, error) {
	panic("implement me")
}

func (hb HttpClient) Create() (*did.Document, error) {
	if response, err := hb.client().CreateDID(context.Background()); err != nil {
		return nil, err
	} else if err := testResponseCode(http.StatusCreated, response); err != nil {
		return nil, err
	} else {
		return readDIDDocument(response.Body)
	}
}

func (hb HttpClient) Get(DID did.DID) (*did.Document, *did.DocumentMetadata, error) {
	return hb.get(DID.String())
}

func (hb HttpClient) GetByTag(tag string) (*did.Document, *did.DocumentMetadata, error) {
	return hb.get("tag:" + tag)
}

func (hb HttpClient) get(identifier string) (*did.Document, *did.DocumentMetadata, error) {
	response, err := hb.client().GetDID(context.Background(), identifier)
	if err != nil {
		return nil, nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, nil, err
	} else {
		// TODO: Parse response
		return nil, nil, nil
	}
}

func (hb HttpClient) Update(DID did.DID, hash []byte, nextVersion did.Document) (*did.Document, error) {
	panic("implement me")
}

func (hb HttpClient) Tag(DID did.DID, tags []string) error {
	panic("implement me")
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
			return nil, fmt.Errorf("unable to unmarshal DID Document response: %w", err)
		}
		return &document, nil
	}
}
