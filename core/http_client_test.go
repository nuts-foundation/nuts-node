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
	"context"
	"errors"
	io2 "io"
	stdHttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		authToken = ""
		client, err := CreateHTTPClient(ClientConfig{}, nil)
		require.NoError(t, err)

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		response, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, stdHttp.StatusOK, response.StatusCode)
		assert.Empty(t, authToken)
	})
	t.Run("with auth token", func(t *testing.T) {
		authToken = ""
		client, err := CreateHTTPClient(ClientConfig{
			Token: "test",
		}, nil)
		require.NoError(t, err)

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		response, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, stdHttp.StatusOK, response.StatusCode)
		assert.Equal(t, "Bearer test", authToken)
	})
	t.Run("with custom token builder", func(t *testing.T) {
		client, err := CreateHTTPClient(ClientConfig{}, newLegacyTokenGenerator("test"))
		require.NoError(t, err)

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		response, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, stdHttp.StatusOK, response.StatusCode)
		assert.Equal(t, "Bearer test", authToken)
	})
	t.Run("with errored token builder", func(t *testing.T) {
		client, err := CreateHTTPClient(ClientConfig{}, newErrorTokenBuilder())
		require.NoError(t, err)

		req, _ := stdHttp.NewRequest(stdHttp.MethodGet, server.URL, nil)
		_, err = client.Do(req)

		assert.EqualError(t, err, "failed to generate authorization token: error")
	})
}

func TestUserAgentRequestEditor(t *testing.T) {
	GitVersion = ""
	req := &stdHttp.Request{Header: map[string][]string{}}

	err := UserAgentRequestEditor(context.TODO(), req)

	assert.NoError(t, err)
	assert.Equal(t, "nuts-node-refimpl/unknown", req.UserAgent())
}

func TestTestResponseCode(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, TestResponseCode(stdHttp.StatusOK, &stdHttp.Response{StatusCode: stdHttp.StatusOK}))
	})
	t.Run("error", func(t *testing.T) {
		data := []byte{1, 2, 3}
		status := stdHttp.StatusUnauthorized

		err := TestResponseCode(stdHttp.StatusOK, &stdHttp.Response{StatusCode: status, Body: readCloser(data)})

		assert.Error(t, err)
		require.ErrorAs(t, err, new(HttpError))
		assert.Equal(t, data, err.(HttpError).ResponseBody)
		assert.Equal(t, status, err.(HttpError).StatusCode)
	})
}

type readCloser []byte

func (r readCloser) Read(p []byte) (n int, err error) {
	copy(p, r)
	return len(r), io2.EOF
}

func (r readCloser) Close() error {
	return nil
}

func newErrorTokenBuilder() AuthorizationTokenGenerator {
	return func() (string, error) {
		return "", errors.New("error")
	}
}
