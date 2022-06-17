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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

type handler struct {
	statusCode   int
	responseData []byte
}

func (h handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.WriteHeader(h.statusCode)
	writer.Write(h.responseData)
}

func TestHttpClient_ListTransactions(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := dag.CreateTestTransactionWithJWK(1)
		data, _ := json.Marshal([]string{string(expected.Data())})
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: data})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.ListTransactions()
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, actual, 1) {
			return
		}
		assert.Equal(t, expected, actual[0])
	})
}

func TestHttpClient_GetTransaction(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := dag.CreateTestTransactionWithJWK(1)
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: expected.Data()})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransaction(expected.Ref())
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("not found (404)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransaction(hash.EmptyHash())
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("server error (500)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransaction(hash.EmptyHash())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHttpClient_GetTransactionPayload(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := []byte{5, 4, 3, 2, 1}
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: expected})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransactionPayload(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("not found (404)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransactionPayload(hash.EmptyHash())
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("server error (500)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetTransactionPayload(hash.EmptyHash())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHTTPClient_GetPeerDiagnostics(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := map[transport.PeerID]PeerDiagnostics{"foo": {Uptime: 50 * time.Second}}
		expectedData, _ := json.Marshal(expected)
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: expectedData})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetPeerDiagnostics()
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("server error (500)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetPeerDiagnostics()
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHTTPClient_Reprocess(t *testing.T) {
	t.Run("202", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusAccepted})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := httpClient.Reprocess("application/did+json")
		assert.NoError(t, err)
	})
	t.Run("bad request (400)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusBadRequest})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		err := httpClient.Reprocess("")
		assert.Error(t, err)
	})
}
