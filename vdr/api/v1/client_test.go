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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"schneider.vip/problem"
)

func TestHTTPClient_Create(t *testing.T) {
	didDoc := did.Document{
		ID: vdr.TestDIDA,
	}

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: didDoc})
		c := getClient(s.URL)
		doc, err := c.Create(DIDCreateRequest{})
		require.NoError(t, err)
		assert.NotNil(t, doc)
	})

	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := getClient(s.URL)
		_, err := c.Create(DIDCreateRequest{})
		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := getClient("not_an_address")
		_, err := c.Create(DIDCreateRequest{})
		assert.Error(t, err)
	})
}

func TestHttpClient_Get(t *testing.T) {
	didDoc := did.Document{
		ID: vdr.TestDIDA,
	}
	meta := resolver.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		resolutionResult := DIDResolutionResult{
			Document:         didDoc,
			DocumentMetadata: meta,
		}
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: resolutionResult})
		c := getClient(s.URL)
		doc, meta, err := c.Get(vdr.TestDIDA.String())
		require.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, meta)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNotFound, ResponseData: ""})
		c := getClient(s.URL)

		_, _, err := c.Get(vdr.TestDIDA.String())

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"})
		c := getClient(s.URL)

		_, _, err := c.Get(vdr.TestDIDA.String())

		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := getClient("not_an_address")
		_, _, err := c.Get(vdr.TestDIDA.String())
		assert.Error(t, err)
	})
}

func TestHTTPClient_ConflictedDIDs(t *testing.T) {
	didDoc := did.Document{
		ID: vdr.TestDIDA,
	}
	meta := resolver.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		resolutionResults := []DIDResolutionResult{{
			Document:         didDoc,
			DocumentMetadata: meta,
		}}
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: resolutionResults})
		c := getClient(s.URL)
		docs, err := c.ConflictedDIDs()
		require.NoError(t, err)
		assert.NotNil(t, docs)
	})

	t.Run("error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: problem.Problem{}})
		c := getClient(s.URL)

		_, err := c.ConflictedDIDs()

		assert.Error(t, err)
	})
}

func TestHTTPClient_Update(t *testing.T) {
	didDoc := did.Document{
		ID: vdr.TestDIDA,
	}
	hash := "0000000000000000000000000000000000000000"

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: didDoc})
		c := getClient(s.URL)
		doc, err := c.Update(vdr.TestDIDA.String(), hash, didDoc)
		require.NoError(t, err)
		assert.NotNil(t, doc)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNotFound, ResponseData: ""})
		c := getClient(s.URL)

		_, err := c.Update(vdr.TestDIDA.String(), hash, didDoc)

		assert.Error(t, err)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"})
		c := getClient(s.URL)

		_, err := c.Update(vdr.TestDIDA.String(), hash, didDoc)

		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := getClient("not_an_address")
		_, err := c.Update(vdr.TestDIDA.String(), hash, didDoc)
		assert.Error(t, err)
	})
}

func TestHTTPClient_Deactivate(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK})
		c := getClient(s.URL)
		err := c.Deactivate(vdr.TestDIDA.String())
		require.NoError(t, err)
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := getClient("not_an_address")
		err := c.Deactivate(vdr.TestDIDA.String())
		assert.Error(t, err)
	})
}
func TestHTTPClient_AddNewVerificationMethod(t *testing.T) {
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	method, _ := did.NewVerificationMethod(vdr.TestMethodDIDA, ssi.JsonWebKey2020, vdr.TestDIDA, pair.PublicKey)
	methodJSON, _ := json.Marshal(method)

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: string(methodJSON)})
		c := getClient(s.URL)
		methodResponse, err := c.AddNewVerificationMethod(vdr.TestDIDA.String())
		require.NoError(t, err)
		assert.Equal(t, method, methodResponse)
	})

	t.Run("error - a non 200 response", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusForbidden})
		c := getClient(s.URL)
		_, err := c.AddNewVerificationMethod(vdr.TestDIDA.String())
		assert.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 403 (expected: 200)")
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := getClient("not_an_address")
		_, err := c.AddNewVerificationMethod(vdr.TestDIDA.String())
		assert.Error(t, err)
	})
}

func TestHTTPClient_DeleteVerificationMethod(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNoContent})
		c := getClient(s.URL)
		err := c.DeleteVerificationMethod(vdr.TestDIDA.String(), vdr.TestMethodDIDA.String())
		require.NoError(t, err)
	})

	t.Run("error - a non 204 response", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusForbidden})
		c := getClient(s.URL)
		err := c.DeleteVerificationMethod(vdr.TestDIDA.String(), vdr.TestMethodDIDA.String())
		assert.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 403 (expected: 204)")
	})

	t.Run("error - server problems", func(t *testing.T) {
		c := getClient("not_an_address")
		err := c.DeleteVerificationMethod(vdr.TestDIDA.String(), vdr.TestMethodDIDA.String())
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

func TestReadVerificationMethod(t *testing.T) {
	t.Run("error - faulty stream", func(t *testing.T) {
		_, err := readVerificationMethod(errReader{})
		assert.Error(t, err)
	})
}

type errReader struct{}

func (e errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("b00m!")
}

func getClient(url string) *HTTPClient {
	return &HTTPClient{
		ClientConfig: core.ClientConfig{
			Address: url, Timeout: time.Second,
		},
	}
}
