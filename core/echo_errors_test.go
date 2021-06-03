package core

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"schneider.vip/problem"
	"testing"
)

type stubRouter map[error]int

func (s stubRouter) ErrorStatusCodes() map[error]int {
	return s
}

func (s stubRouter) Routes(router EchoRouter) {
	panic("implement me")
}

func TestHttpErrorHandler(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	es, _ := createEchoServer(HTTPConfig{}, false, []Routable{
		stubRouter(map[error]int{err1: 401}),
		stubRouter(map[error]int{err2: 402}),
	})
	server := httptest.NewServer(es)
	client := http.Client{}

	t.Run("is echo HTTPError", func(t *testing.T) {
		f := func(c echo.Context) error {
			err := errors.New("failed")
			return &echo.HTTPError{
				Code:     http.StatusForbidden,
				Message:  err.Error(),
				Internal: err,
			}
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"failed\",\"status\":403,\"title\":\"Operation failed\"}", string(bodyBytes))
	})
	t.Run("error mapping from globals", func(t *testing.T) {
		f := func(c echo.Context) error {
			c.Set(operationIDContextKey, "test")
			return err1
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"error 1\",\"status\":401,\"title\":\"test failed\"}", string(bodyBytes))
	})
	t.Run("error mapping from context", func(t *testing.T) {
		f := func(c echo.Context) error {
			c.Set(operationIDContextKey, "test")
			c.Set(statusCodesContextKey, map[error]int{err2: 402})
			return err2
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 402, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"error 2\",\"status\":402,\"title\":\"test failed\"}", string(bodyBytes))
	})
	t.Run("unmapped", func(t *testing.T) {
		f := func(c echo.Context) error {
			c.Set(operationIDContextKey, "test")
			return errors.New("other error")
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 500, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"other error\",\"status\":500,\"title\":\"test failed\"}", string(bodyBytes))
	})
}

func Test_NotFoundError(t *testing.T) {
	err := NotFoundError("failed: %s", "oops").(httpStatusCodeError)
	assert.EqualError(t, err, "failed: oops")
	assert.Equal(t, http.StatusNotFound, err.statusCode)
	assert.ErrorIs(t, err, NotFoundError(""))
}

func Test_InvalidInputError(t *testing.T) {
	err := InvalidInputError("failed: %s", "oops").(httpStatusCodeError)
	assert.EqualError(t, err, "failed: oops")
	assert.Equal(t, http.StatusBadRequest, err.statusCode)
	assert.ErrorIs(t, err, InvalidInputError(""))
}
