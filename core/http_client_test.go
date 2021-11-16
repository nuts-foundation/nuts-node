package core

import (
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	io2 "io"
	stdHttp "net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClient(t *testing.T) {
	var authToken string
	var handler stdHttp.HandlerFunc = func(res stdHttp.ResponseWriter, req *stdHttp.Request) {
		authToken = req.Header.Get("Authorization")
		res.WriteHeader(stdHttp.StatusOK)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	t.Run("no auth token", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}

		authToken = ""
		client, err := CreateHTTPClient(ClientConfig{})
		if !assert.NoError(t, err) {
			return
		}

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		response, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, stdHttp.StatusOK, response.StatusCode)
		assert.Empty(t, authToken)
	})
	t.Run("with auth token", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}

		authToken = ""
		client, err := CreateHTTPClient(ClientConfig{
			Token: "test",
		})
		if !assert.NoError(t, err) {
			return
		}

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		response, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, stdHttp.StatusOK, response.StatusCode)
		assert.Equal(t, "Bearer test", authToken)
	})
}

func TestTestResponseCode(t *testing.T) {
	assert.NoError(t, TestResponseCode(stdHttp.StatusOK, &stdHttp.Response{StatusCode: stdHttp.StatusOK}))
	assert.Error(t, TestResponseCode(stdHttp.StatusOK, &stdHttp.Response{StatusCode: stdHttp.StatusUnauthorized, Body: readCloser([]byte{1, 2, 3})}))
}

type readCloser []byte

func (r readCloser) Read(p []byte) (n int, err error) {
	copy(p, r)
	return 0, io2.EOF
}

func (r readCloser) Close() error {
	return nil
}
