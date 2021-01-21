/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	did2 "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

type handler struct {
	statusCode   int
	responseData interface{}
}

func (h handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.WriteHeader(h.statusCode)
	bytes, _ := json.Marshal(h.responseData)
	writer.Write(bytes)
}

func TestHTTPClient_Create(t *testing.T) {
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := did2.Document{
		ID: *did,
	}

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: didDoc})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, err := c.Create()
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
	})

	t.Run("error - other", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		_, err := c.Create()
		assert.Error(t, err)
	})
}

func TestHttpClient_Get(t *testing.T) {
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := &did2.Document{
		ID: *did,
	}
	meta := &types.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		resolutionResult := DIDResolutionResult{
			Document:         didDoc,
			DocumentMetadata: meta,
		}
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: resolutionResult})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, meta, err := c.Get(*did)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
		assert.NotNil(t, meta)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound, responseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, _, err := c.Get(*did)

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: "}"})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, _, err := c.Get(*did)

		assert.Error(t, err)
	})
}

func TestHTTPClient_Update(t *testing.T) {
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := did2.Document{
		ID: *did,
	}
	hash, _ := hash.ParseHex("0000000000000000000000000000000000000000")

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: didDoc})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, err := c.Update(*did, hash, didDoc)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound, responseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, err := c.Update(*did, hash, didDoc)

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: "}"})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, err := c.Update(*did, hash, didDoc)

		assert.Error(t, err)
	})
}
