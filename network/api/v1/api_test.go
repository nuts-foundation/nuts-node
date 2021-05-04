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
	"errors"
	test2 "github.com/nuts-foundation/nuts-node/test"
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

func TestApiWrapper_GetTransaction(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	transaction := dag.CreateTestTransactionWithJWK(1)
	path := "/transaction/:ref"

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransaction(hash.EqHash(transaction.Ref())).Return(transaction, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(transaction.Ref().String())

		err := wrapper.GetTransaction(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/jose", rec.Header().Get("Content-Type"))
		assert.Equal(t, string(transaction.Data()), rec.Body.String())
	})
	t.Run("error", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransaction(gomock.Any()).Return(nil, errors.New("failed"))

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(hash.SHA256Sum([]byte{1, 2, 3}).String())

		err := wrapper.GetTransaction(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransaction, err)
		test2.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test2.AssertErrProblemDetail(t, "failed", err)
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

		err := wrapper.GetTransaction(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransaction, err)
		test2.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test2.AssertErrProblemDetail(t, "incorrect hash length (2)", err)
	})
	t.Run("not found", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransaction(gomock.Any()).Return(nil, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(transaction.Ref().String())

		err := wrapper.GetTransaction(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransaction, err)
		test2.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test2.AssertErrProblemDetail(t, "transaction not found", err)
	})
}

func TestApiWrapper_RenderGraph(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().Walk(gomock.Any())

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/graph")

		err := wrapper.RenderGraph(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/vnd.graphviz", rec.Header().Get("Content-Type"))
		assert.NotEmpty(t, rec.Body.String())
	})
	t.Run("error", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().Walk(gomock.Any()).Return(errors.New("failed"))

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/graph")

		err := wrapper.RenderGraph(c)
		test2.AssertErrProblemTitle(t, problemTitleRenderGraph, err)
		test2.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test2.AssertErrProblemDetail(t, "failed", err)
	})
}

func TestApiWrapper_GetTransactionPayload(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	transaction := dag.CreateTestTransactionWithJWK(1)
	path := "/transaction/:ref/payload"

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransactionPayload(hash.EqHash(transaction.Ref())).Return(payload, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(transaction.Ref().String())

		err := wrapper.GetTransactionPayload(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, string(payload), rec.Body.String())
	})
	t.Run("error", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransactionPayload(gomock.Any()).Return(nil, errors.New("failed"))

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(transaction.Ref().String())

		err := wrapper.GetTransactionPayload(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransactionPayload, err)
		test2.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test2.AssertErrProblemDetail(t, "failed", err)
	})
	t.Run("not found", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().GetTransactionPayload(gomock.Any()).Return(nil, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath(path)
		c.SetParamNames("ref")
		c.SetParamValues(transaction.Ref().String())

		err := wrapper.GetTransactionPayload(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransactionPayload, err)
		test2.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test2.AssertErrProblemDetail(t, "transaction or contents not found", err)
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

		err := wrapper.GetTransactionPayload(c)
		test2.AssertErrProblemTitle(t, problemTitleGetTransactionPayload, err)
		test2.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test2.AssertErrProblemDetail(t, "incorrect hash length (2)", err)
	})
}

func TestApiWrapper_ListTransactions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	transaction := dag.CreateTestTransactionWithJWK(1)

	t.Run("200", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().ListTransactions().Return([]dag.Transaction{transaction}, nil)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/transaction")

		err := wrapper.ListTransactions(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, `["`+string(transaction.Data())+`"]`, strings.TrimSpace(rec.Body.String()))
	})
	t.Run("error", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().ListTransactions().Return(nil, errors.New("failed"))

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/transaction")

		err := wrapper.ListTransactions(c)
		test2.AssertErrProblemTitle(t, problemTitleListTransactions, err)
		test2.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test2.AssertErrProblemDetail(t, "failed", err)
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
