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

package http

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
)

func Test_MultiEcho_Bind(t *testing.T) {
	const defaultAddress = ":1323"
	t.Run("group already bound", func(t *testing.T) {
		m := NewMultiEcho()
		err := m.Bind("", defaultAddress, func() (EchoServer, error) {
			return echo.New(), nil
		})
		require.NoError(t, err)
		err = m.Bind("", defaultAddress, func() (EchoServer, error) {
			return echo.New(), nil
		})
		assert.EqualError(t, err, "http bind already exists: /")
	})
	t.Run("error - group contains subpaths", func(t *testing.T) {
		m := NewMultiEcho()
		err := m.Bind("internal/vdr", defaultAddress, nil)
		assert.EqualError(t, err, "bind can't contain subpaths: internal/vdr")
	})
}

func Test_MultiEcho_Start(t *testing.T) {
	t.Run("error while starting returns first error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		server := NewMockEchoServer(ctrl)
		server.EXPECT().Start(gomock.Any()).Return(errors.New("unable to start"))

		m := NewMultiEcho()
		m.Bind("group2", ":8080", func() (EchoServer, error) {
			return server, nil
		})
		err := m.Start()
		assert.EqualError(t, err, "unable to start")
	})
}

func Test_MultiEcho(t *testing.T) {
	ctrl := gomock.NewController(t)

	const defaultAddress = ":1323"

	// WithParam up expected echo servers
	defaultServer := NewMockEchoServer(ctrl)
	defaultServer.EXPECT().Add("PATCH", "/other/default-endpoint", gomock.Any())
	defaultServer.EXPECT().Start(defaultAddress)

	internalServer := NewMockEchoServer(ctrl)
	internalServer.EXPECT().Add("GET", "/internal/internal-endpoint", gomock.Any())
	internalServer.EXPECT().Start("internal:8080")

	publicServer := NewMockEchoServer(ctrl)
	publicServer.EXPECT().Add(http.MethodPost, "/public/pub-endpoint", gomock.Any())
	publicServer.EXPECT().Add(http.MethodDelete, "/extra-public/extra-pub-endpoint", gomock.Any())
	publicServer.EXPECT().Start("public:8080")

	// Bind interfaces
	m := NewMultiEcho()
	err := m.Bind(RootPath, defaultAddress, func() (EchoServer, error) {
		return defaultServer, nil
	})
	require.NoError(t, err)
	err = m.Bind("internal", "internal:8080", func() (EchoServer, error) {
		return internalServer, nil
	})
	require.NoError(t, err)
	err = m.Bind("public", "public:8080", func() (EchoServer, error) {
		return publicServer, nil
	})
	require.NoError(t, err)
	err = m.Bind("extra-public", "public:8080", func() (EchoServer, error) {
		t.Fatal("should not be called!")
		return nil, nil
	})
	require.NoError(t, err)

	m.addFn(http.MethodPost, "/public/pub-endpoint", nil)
	m.addFn(http.MethodDelete, "/extra-public/extra-pub-endpoint", nil)
	m.addFn(http.MethodGet, "/internal/internal-endpoint", nil)
	m.addFn(http.MethodPatch, "/other/default-endpoint", nil)

	err = m.Start()
	require.NoError(t, err)
}

func Test_MultiEcho_Methods(t *testing.T) {
	ctrl := gomock.NewController(t)

	defaultServer := NewMockEchoServer(ctrl)
	gomock.InOrder(
		defaultServer.EXPECT().Add("GET", "/get", gomock.Any()),
		defaultServer.EXPECT().Add("POST", "/post", gomock.Any()),
		defaultServer.EXPECT().Add("PUT", "/put", gomock.Any()),
		defaultServer.EXPECT().Add("DELETE", "/delete", gomock.Any()),
		defaultServer.EXPECT().Add("PATCH", "/patch", gomock.Any()),
		defaultServer.EXPECT().Add("HEAD", "/head", gomock.Any()),
		defaultServer.EXPECT().Add("OPTIONS", "/options", gomock.Any()),
		defaultServer.EXPECT().Add("CONNECT", "/connect", gomock.Any()),
		defaultServer.EXPECT().Add("TRACE", "/trace", gomock.Any()),
		defaultServer.EXPECT().Use(gomock.Any()),
	)

	m := NewMultiEcho()
	m.Bind(RootPath, ":1323", func() (EchoServer, error) {
		return defaultServer, nil
	})
	m.GET("/get", nil)
	m.POST("/post", nil)
	m.PUT("/put", nil)
	m.DELETE("/delete", nil)
	m.PATCH("/patch", nil)
	m.HEAD("/head", nil)
	m.OPTIONS("/options", nil)
	m.CONNECT("/connect", nil)
	m.TRACE("/trace", nil)
	m.Use(nil)
}

func Test_getBindFromPath(t *testing.T) {
	m := NewMultiEcho()
	assert.Equal(t, "/internal", m.getBindFromPath("/internal/vdr/v1/did"))
	assert.Equal(t, "/internal", m.getBindFromPath("/internal"))
	assert.Equal(t, "/internal", m.getBindFromPath("internal"))
	assert.Equal(t, "/internal", m.getBindFromPath("internal/"))
	assert.Equal(t, "/", m.getBindFromPath(""))
	assert.Equal(t, "/", m.getBindFromPath("/"))
}
