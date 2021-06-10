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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

var payload = []byte("Hello, World!")

func TestApiWrapper_GetTransaction(t *testing.T) {
	r := GetPeerDiagnosticsResponse{
		JSON200:      &struct {
			AdditionalProperties map[string]PeerDiagnostics `json:"-"`
		}{
			AdditionalProperties: map[string]PeerDiagnostics{"peer": {
				Uptime:               10,
				Peers:                nil,
				NumberOfTransactions: 5,
				Version:              "",
				Vendor:               "aaa",
			}},
		},
	}
	bytes, _ := json.Marshal(r.JSON200)
	println(string(bytes))

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

		assert.EqualError(t, err, "failed")
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

		assert.EqualError(t, err, "invalid hash: incorrect hash length (2)")
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

		assert.EqualError(t, err, "transaction not found")
	})
}

func TestApiWrapper_GetPeerDiagnostics(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var networkClient = network.NewMockTransactions(mockCtrl)
	e, wrapper := initMockEcho(networkClient)
	networkClient.EXPECT().PeerDiagnostics().Return(map[p2p.PeerID]proto.Diagnostics{"foo": {
		Uptime:               1000 * time.Second,
		Peers:                []p2p.PeerID{"bar"},
		NumberOfTransactions: 5,
		Version:              "1.0",
		Vendor:               "Test",
	}})

	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/diagnostics/peers")

	err := wrapper.GetPeerDiagnostics(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=UTF-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, `{"foo":{"uptime":1000,"peers":["bar"],"transactionNum":5,"version":"1.0","vendor":"Test"}}`, strings.TrimSpace(rec.Body.String()))
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

		assert.EqualError(t, err, "failed")
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

		assert.EqualError(t, err, "failed")
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

		assert.EqualError(t, err, "transaction or contents not found")
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

		assert.EqualError(t, err, "invalid hash: incorrect hash length (2)")
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

		assert.EqualError(t, err, "failed")
	})
}

func TestWrapper_GetPeerDiagnostics(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	t.Run("200", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		expected := map[p2p.PeerID]proto.Diagnostics{"foo": {Uptime: 50 * time.Second}}
		networkClient.EXPECT().PeerDiagnostics().Return(expected)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/diagnostics/peers")

		err := wrapper.GetPeerDiagnostics(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		actual := map[p2p.PeerID]PeerDiagnostics{}
		json.Unmarshal(rec.Body.Bytes(), &actual)
		assert.Equal(t, PeerDiagnostics(expected["foo"]), actual["foo"])
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
