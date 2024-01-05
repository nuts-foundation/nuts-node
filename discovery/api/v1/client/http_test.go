package client

import (
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
	testHTTP "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPInvoker_Register(t *testing.T) {
	vp := vc.VerifiablePresentation{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
	}
	vpData, _ := vp.MarshalJSON()
	t.Run("ok", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusCreated}
		server := httptest.NewServer(handler)
		client := New(server.Client())

		err := client.Register(context.Background(), server.URL, vp)

		assert.NoError(t, err)
		assert.Equal(t, http.MethodPost, handler.Request.Method)
		assert.Equal(t, "application/json", handler.Request.Header.Get("Content-Type"))
		assert.Equal(t, vpData, handler.RequestData)
	})
	t.Run("non-ok", func(t *testing.T) {
		server := httptest.NewServer(&testHTTP.Handler{StatusCode: http.StatusInternalServerError})
		client := New(server.Client())

		err := client.Register(context.Background(), server.URL, vp)

		assert.ErrorContains(t, err, "non-OK response from remote Discovery Service")
	})
}

func TestHTTPInvoker_Get(t *testing.T) {
	vp := vc.VerifiablePresentation{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
	}
	const clientTag = "client-tag"
	const serverTag = "server-tag"
	t.Run("no tag from client", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = map[string]interface{}{
			"entries": []interface{}{vp},
			"tag":     serverTag,
		}
		server := httptest.NewServer(handler)
		client := New(server.Client())

		presentations, tag, err := client.Get(context.Background(), server.URL, nil)

		assert.NoError(t, err)
		assert.Len(t, presentations, 1)
		assert.Empty(t, handler.RequestQuery.Get("tag"))
		assert.Equal(t, discovery.Tag(serverTag), *tag)
	})
	t.Run("tag provided by client", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = map[string]interface{}{
			"entries": []interface{}{vp},
			"tag":     serverTag,
		}
		server := httptest.NewServer(handler)
		client := New(server.Client())

		inputTag := discovery.Tag(clientTag)
		presentations, tag, err := client.Get(context.Background(), server.URL, &inputTag)

		assert.NoError(t, err)
		assert.Len(t, presentations, 1)
		assert.Equal(t, clientTag, handler.RequestQuery.Get("tag"))
		assert.Equal(t, discovery.Tag(serverTag), *tag)
	})
	t.Run("server returns invalid status code", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusInternalServerError}
		server := httptest.NewServer(handler)
		client := New(server.Client())

		_, _, err := client.Get(context.Background(), server.URL, nil)

		assert.ErrorContains(t, err, "non-OK response from remote Discovery Service")
	})
	t.Run("server does not return JSON", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = "not json"
		server := httptest.NewServer(handler)
		client := New(server.Client())

		_, _, err := client.Get(context.Background(), server.URL, nil)

		assert.ErrorContains(t, err, "failed to unmarshal response from remote Discovery Service")
	})
}
