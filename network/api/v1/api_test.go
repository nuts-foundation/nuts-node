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
 */

package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

var payload = []byte("Hello, World!")

func TestApiWrapper_GetDocument(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	document := dag.CreateTestDocumentWithJWK(1)
	path := "/document/:ref"

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetDocument(hash.EqHash(document.Ref())).Return(document, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(document.Ref().String())

		err := wrapper.GetDocument(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/jose", rec.Header().Get("Content-Type"))
		assert.Equal(t, string(document.Data()), rec.Body.String())
	})
	t.Run("invalid hash", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues("1234")

		err := wrapper.GetDocument(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "incorrect hash length (2)", rec.Body.String())
	})
	t.Run("not found", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetDocument(gomock.Any()).Return(nil, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(document.Ref().String())

		err := wrapper.GetDocument(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "document not found", rec.Body.String())
	})
}

func TestApiWrapper_GetDocumentPayload(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	document := dag.CreateTestDocumentWithJWK(1)
	path := "/document/:ref/payload"

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetDocumentPayload(hash.EqHash(document.Ref())).Return(payload, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(document.Ref().String())

		err := wrapper.GetDocumentPayload(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, string(payload), rec.Body.String())
	})
	t.Run("not found", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetDocumentPayload(gomock.Any()).Return(nil, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(document.Ref().String())

		err := wrapper.GetDocumentPayload(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "document or contents not found", rec.Body.String())
	})
	t.Run("invalid hash", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues("1234")

		err := wrapper.GetDocumentPayload(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "incorrect hash length (2)", rec.Body.String())
	})
}

func TestApiWrapper_ListDocuments(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	document := dag.CreateTestDocumentWithJWK(1)

	t.Run("list documents", func(t *testing.T) {
		t.Run("200", func(t *testing.T) {
			var networkClient = network.NewMockTransactions(mockCtrl)
			e, wrapper := initMockEcho(networkClient)
			networkClient.EXPECT().ListDocuments().Return([]dag.Document{document}, nil)

			req := httptest.NewRequest(echo.GET, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath("/document")

			err := wrapper.ListDocuments(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, `["`+string(document.Data())+`"]`, strings.TrimSpace(rec.Body.String()))
		})
	})
}

func initMockEcho(networkClient *network.MockTransactions) (*echo.Echo, *ServerInterfaceWrapper) {
	e := echo.New()
	stub := Wrapper{Service: networkClient}
	wrapper := &ServerInterfaceWrapper{
		Handler: stub,
	}
	return e, wrapper
}
