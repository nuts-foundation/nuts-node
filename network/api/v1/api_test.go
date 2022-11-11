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
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/network/transport"

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
		networkClient.EXPECT().GetTransaction(gomock.Any()).Return(nil, dag.ErrTransactionNotFound)

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
	networkClient.EXPECT().PeerDiagnostics().Return(map[transport.PeerID]transport.Diagnostics{"foo": {
		Uptime:               1000 * time.Second,
		Peers:                []transport.PeerID{"bar"},
		NumberOfTransactions: 5,
		SoftwareVersion:      "1.0",
		SoftwareID:           "Test",
	}})

	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/diagnostics/peers")

	err := wrapper.GetPeerDiagnostics(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=UTF-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, `{"foo":{"uptime":1000,"peers":["bar"],"transactionNum":5,"softwareVersion":"1.0","softwareID":"Test"}}`, strings.TrimSpace(rec.Body.String()))
}

func TestApiWrapper_RenderGraph(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	t.Run("ok - no query params", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().ListTransactionsInRange(gomock.Any(), gomock.Any())

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
	t.Run("ok - with query params", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().ListTransactionsInRange(gomock.Any(), gomock.Any())
		q := make(url.Values)
		q.Set("start", "0")
		q.Set("end", "5")

		req := httptest.NewRequest(echo.GET, "/?"+q.Encode(), nil)
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
		q := make(url.Values) // invalid query params exit before ListTransactionsInRange call
		q.Set("start", "5")
		q.Set("end", "0")

		req := httptest.NewRequest(echo.GET, "/?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/graph")

		err := wrapper.RenderGraph(c)
		assert.EqualError(t, err, "invalid range")
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
		networkClient.EXPECT().GetTransactionPayload(gomock.Any()).Return(nil, dag.ErrPayloadNotFound)

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
		networkClient.EXPECT().ListTransactionsInRange(uint32(0), uint32(dag.MaxLamportClock)).Return([]dag.Transaction{transaction}, nil)

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
		networkClient.EXPECT().ListTransactionsInRange(uint32(0), uint32(dag.MaxLamportClock)).Return(nil, errors.New("failed"))

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
		expected := map[transport.PeerID]transport.Diagnostics{"foo": {Uptime: 50 * time.Second}}
		networkClient.EXPECT().PeerDiagnostics().Return(expected)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/diagnostics/peers")

		err := wrapper.GetPeerDiagnostics(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		actual := map[transport.PeerID]PeerDiagnostics{}
		json.Unmarshal(rec.Body.Bytes(), &actual)
		assert.Equal(t, PeerDiagnostics(expected["foo"]), actual["foo"])
	})
}

func TestApiWrapper_Reprocess(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	t.Run("error - missing type", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)

		req := httptest.NewRequest(echo.GET, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/reprocess")

		err := wrapper.Reprocess(c)
		assert.EqualError(t, err, "missing type")
	})
	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		e, wrapper := initMockEcho(networkClient)
		networkClient.EXPECT().Reprocess("application/did+json")

		req := httptest.NewRequest(echo.GET, "/reprocess?type=application/did%2bjson", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/reprocess")

		err := wrapper.Reprocess(c)

		assert.NoError(t, err)
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

func TestWrapper_Preprocess(t *testing.T) {
	ctrl := gomock.NewController(t)
	w := &Wrapper{}
	ctx := mock.NewMockContext(ctrl)
	ctx.EXPECT().Set(core.OperationIDContextKey, "foo")
	ctx.EXPECT().Set(core.ModuleNameContextKey, "Network")

	w.Preprocess("foo", ctx)
}

func TestWrapper_ListEvents(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)
	testEvent := dag.Event{
		Error:       "error",
		Hash:        hash.EmptyHash(),
		Retries:     1,
		Transaction: tx,
		Type:        dag.TransactionEventType,
	}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetwork := network.NewMockTransactions(ctrl)
		ctx := mock.NewMockContext(ctrl)
		w := &Wrapper{Service: mockNetwork}
		subscriberMock := dag.NewMockNotifier(ctrl)
		mockNetwork.EXPECT().Subscribers().Return([]dag.Notifier{subscriberMock})
		subscriberMock.EXPECT().Name().Return("test")
		subscriberMock.EXPECT().GetFailedEvents().Return([]dag.Event{testEvent}, nil)
		var capturedEventSubscriber []EventSubscriber
		ctx.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(
			func(_ interface{}, eventObject interface{}) error {
				capturedEventSubscriber = eventObject.([]EventSubscriber)
				return nil
			})

		err := w.ListEvents(ctx)

		require.NoError(t, err)
		require.Len(t, capturedEventSubscriber, 1)
		assert.Equal(t, "test", capturedEventSubscriber[0].Name)
		require.Len(t, capturedEventSubscriber[0].Events, 1)
		capturedEvent := capturedEventSubscriber[0].Events[0]
		assert.Equal(t, testEvent.Hash.String(), capturedEvent.Hash)
		assert.Equal(t, testEvent.Type, *capturedEvent.Type)
		assert.Equal(t, tx.Ref().String(), capturedEvent.Transaction)
		assert.Equal(t, testEvent.Retries, capturedEvent.Retries)
		assert.Equal(t, testEvent.Error, *capturedEvent.Error)
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetwork := network.NewMockTransactions(ctrl)
		ctx := mock.NewMockContext(ctrl)
		w := &Wrapper{Service: mockNetwork}
		subscriberMock := dag.NewMockNotifier(ctrl)
		mockNetwork.EXPECT().Subscribers().Return([]dag.Notifier{subscriberMock})
		subscriberMock.EXPECT().Name().Return("test")
		subscriberMock.EXPECT().GetFailedEvents().Return(nil, errors.New("error"))

		err := w.ListEvents(ctx)

		assert.Error(t, err)
	})
}
