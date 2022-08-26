/*
 * Copyright (C) 2022 Nuts community
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
