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

func TestHttpClient_ListDocuments(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := dag.CreateTestDocumentWithJWK(1)
		data, _ := json.Marshal([]string{string(expected.Data())})
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: data})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.ListDocuments()
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, actual, 1) {
			return
		}
		assert.Equal(t, expected, actual[0])
	})
}

func TestHttpClient_GetDocument(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := dag.CreateTestDocumentWithJWK(1)
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: expected.Data()})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocument(expected.Ref())
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("not found (404)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocument(hash.EmptyHash())
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("server error (500)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocument(hash.EmptyHash())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHttpClient_GetDocumentPayload(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		expected := []byte{5, 4, 3, 2, 1}
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: expected})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocumentPayload(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("not found (404)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusNotFound})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocumentPayload(hash.EmptyHash())
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("server error (500)", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError})
		httpClient := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		actual, err := httpClient.GetDocumentPayload(hash.EmptyHash())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}
