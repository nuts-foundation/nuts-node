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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestHTTPClient_Create(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := did.Document{
		ID: *id,
	}

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: didDoc})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, err := c.Create()
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
	})

	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		_, err := c.Create()
		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		_, err := c.Create()
		assert.Error(t, err)
	})
}

func TestHttpClient_Get(t *testing.T) {
	didString := "did:nuts:1"
	id, _ := did.ParseDID(didString)
	didDoc := did.Document{
		ID: *id,
	}
	meta := types.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		resolutionResult := DIDResolutionResult{
			Document:         didDoc,
			DocumentMetadata: meta,
		}
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: resolutionResult})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, meta, err := c.Get(didString)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
		assert.NotNil(t, meta)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, _, err := c.Get(didString)

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, _, err := c.Get(didString)

		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		_, _, err := c.Get(didString)
		assert.Error(t, err)
	})
}

func TestHTTPClient_Update(t *testing.T) {
	didString := "did:nuts:1"
	id, _ := did.ParseDID(didString)
	didDoc := did.Document{
		ID: *id,
	}
	hash := "0000000000000000000000000000000000000000"

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: didDoc})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		doc, err := c.Update(didString, hash, didDoc)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, doc)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: ""})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, err := c.Update(didString, hash, didDoc)

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}

		_, err := c.Update(didString, hash, didDoc)

		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		_, err := c.Update(didString, hash, didDoc)
		assert.Error(t, err)
	})
}
func TestHTTPClient_Deactivate(t *testing.T) {
	didString := "did:nuts:1"

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.Deactivate(didString)
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		err := c.Deactivate(didString)
		assert.Error(t, err)
	})
}

func TestHTTPClient_AddNewVerificationMethod(t *testing.T) {
	didString := "did:nuts:1"
	id123, _ := did.ParseDID(didString)
	id123Method, _ := did.ParseDID("did:nuts:123#abc-method")
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	method, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, *id123, pair.PublicKey)
	methodJSON, _ := json.Marshal(method)

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusCreated, ResponseData: string(methodJSON)})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		// methodResponse, err := c.AddNewVerificationMethod(didString)
		_, err := c.AddNewVerificationMethod(didString)
		if !assert.NoError(t, err) {
			return
		}
		// this fails because of https://github.com/nuts-foundation/go-did/issues/33
		//assert.Equal(t, method, methodResponse)
	})

	t.Run("error - a non 201 response", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusForbidden})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		_, err := c.AddNewVerificationMethod(didString)
		assert.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 403 (expected: 201), response: null")
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		_, err := c.AddNewVerificationMethod(didString)
		assert.Error(t, err)
	})
}

func TestHTTPClient_DeleteVerificationMethod(t *testing.T) {
	didString := "did:nuts:1"
	didMethodString := "did:nuts:123#abc-method-1"

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNoContent})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.DeleteVerificationMethod(didString, didMethodString)
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - a non 204 response", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusForbidden})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := c.DeleteVerificationMethod(didString, didMethodString)
		assert.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 403 (expected: 204), response: null")
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := HTTPClient{ServerAddress: "not_an_address", Timeout: time.Second}
		err := c.DeleteVerificationMethod(didString, didMethodString)
		assert.Error(t, err)
	})
}

func TestReadDIDDocument(t *testing.T) {
	t.Run("error - faulty stream", func(t *testing.T) {
		_, err := readDIDDocument(errReader{})
		assert.Error(t, err)
	})
}

func TestReadDIDResolutionResult(t *testing.T) {
	t.Run("error - faulty stream", func(t *testing.T) {
		_, err := readDIDResolutionResult(errReader{})
		assert.Error(t, err)
	})
}

type errReader struct{}

func (e errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("b00m!")
}
