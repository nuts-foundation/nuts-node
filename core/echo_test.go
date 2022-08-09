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

package core

import (
	"errors"
	"fmt"
	nutsTest "github.com/nuts-foundation/nuts-node/test"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func Test_MultiEcho_Bind(t *testing.T) {
	t.Run("group already bound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := NewServerConfig().HTTP.HTTPConfig
		m, _ := NewMultiEcho(func(_ HTTPConfig) (EchoServer, EchoStarter, error) {
			return NewMockEchoServer(ctrl), nil, nil
		}, cfg)
		err := m.Bind("", cfg)
		assert.EqualError(t, err, "http bind group already exists: ")
	})
}

func Test_MultiEcho_Start(t *testing.T) {
	t.Run("error while starting returns first error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := NewServerConfig().HTTP.HTTPConfig
		m, _ := NewMultiEcho(func(_ HTTPConfig) (EchoServer, EchoStarter, error) {
			server := NewMockEchoServer(ctrl)
			server.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("unable to start"))
			return server, func(addr string) error {
				return server.Start(addr)
			}, nil
		}, cfg)
		m.Bind("group2", HTTPConfig{Address: ":8080"})
		err := m.Start()
		assert.EqualError(t, err, "unable to start")
	})
}

func Test_MultiEcho(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defaultHttpCfg := NewServerConfig().HTTP.HTTPConfig

	// Set up expected echo servers
	defaultServer := NewMockEchoServer(ctrl)
	defaultServer.EXPECT().Add("PATCH", "/other/default-endpoint", gomock.Any())
	defaultServer.EXPECT().Start(defaultHttpCfg.Address)

	internalServer := NewMockEchoServer(ctrl)
	internalServer.EXPECT().Add("GET", "/internal/internal-endpoint", gomock.Any())
	internalServer.EXPECT().Start("internal:8080")

	publicServer := NewMockEchoServer(ctrl)
	publicServer.EXPECT().Add(http.MethodPost, "/public/pub-endpoint", gomock.Any())
	publicServer.EXPECT().Add(http.MethodDelete, "/extra-public/extra-pub-endpoint", gomock.Any())
	publicServer.EXPECT().Start("public:8080")

	createFnCalled := 0
	createFn := func(_ HTTPConfig) (EchoServer, EchoStarter, error) {
		servers := []EchoServer{defaultServer, internalServer, publicServer}
		s := servers[createFnCalled]
		createFnCalled++
		return s, s.Start, nil
	}

	// Bind interfaces
	m, _ := NewMultiEcho(createFn, defaultHttpCfg)
	err := m.Bind("internal", HTTPConfig{Address: "internal:8080"})
	if !assert.NoError(t, err) {
		return
	}
	err = m.Bind("public", HTTPConfig{Address: "public:8080"})
	if !assert.NoError(t, err) {
		return
	}
	err = m.Bind("extra-public", HTTPConfig{Address: "public:8080"})
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, 3, createFnCalled)

	m.Add(http.MethodPost, "/public/pub-endpoint", nil)
	m.Add(http.MethodDelete, "/extra-public/extra-pub-endpoint", nil)
	m.Add(http.MethodGet, "/internal/internal-endpoint", nil)
	m.Add(http.MethodPatch, "/other/default-endpoint", nil)

	err = m.Start()
	if !assert.NoError(t, err) {
		return
	}
}

func Test_MultiEcho_Methods(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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

	createFn := func(_ HTTPConfig) (EchoServer, EchoStarter, error) {
		return defaultServer, nil, nil
	}

	m, _ := NewMultiEcho(createFn, NewServerConfig().HTTP.HTTPConfig)
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

func Test_getGroup(t *testing.T) {
	assert.Equal(t, "internal", getGroup("/internal/vdr/v1/did"))
	assert.Equal(t, "internal", getGroup("/internal"))
	assert.Equal(t, "internal", getGroup("internal"))
	assert.Equal(t, "internal", getGroup("internal/"))
	assert.Equal(t, "", getGroup(""))
	assert.Equal(t, "", getGroup("/"))
}

func Test_createEchoServer(t *testing.T) {
	t.Run("ok, no TLS", func(t *testing.T) {
		instance, starter, err := createEchoServer(NewServerConfig().HTTP.HTTPConfig, nil, true, true)
		assert.NotNil(t, instance)
		assert.NotNil(t, starter)
		assert.NoError(t, err)
	})
	t.Run("TLS", func(t *testing.T) {
		serverCfg := NewServerConfig()
		serverCfg.TLS.CertFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.CertKeyFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.TrustStoreFile = "../test/pki/truststore.pem"
		serverCfg.TLS.Enabled = true
		tlsConfig, err := serverCfg.TLS.Load()
		if !assert.NoError(t, err) {
			return
		}

		t.Run("error - TLS not configured", func(t *testing.T) {
			httpCfg := serverCfg.HTTP.HTTPConfig
			httpCfg.TLSMode = ServerCertTLSMode

			instance, starter, err := createEchoServer(httpCfg, nil, true, false)

			assert.Nil(t, instance)
			assert.Nil(t, starter)
			assert.EqualError(t, err, "TLS must be enabled (without offloading) to enable it on HTTP endpoints")
		})
		t.Run("server certificate", func(t *testing.T) {
			port := nutsTest.FreeTCPPort()
			httpCfg := serverCfg.HTTP.HTTPConfig
			httpCfg.TLSMode = ServerCertTLSMode
			httpCfg.Address = fmt.Sprintf("localhost:%d", port)

			instance, starter, err := createEchoServer(httpCfg, tlsConfig, true, false)

			assert.NotNil(t, instance)
			assert.NotNil(t, starter)
			assert.NoError(t, err)
		})
		t.Run("client certificate", func(t *testing.T) {
			port := nutsTest.FreeTCPPort()
			httpCfg := serverCfg.HTTP.HTTPConfig
			httpCfg.TLSMode = MutualTLSMode
			httpCfg.Address = fmt.Sprintf("localhost:%d", port)

			instance, starter, err := createEchoServer(httpCfg, tlsConfig, true, false)

			assert.NotNil(t, instance)
			assert.NotNil(t, starter)
			assert.NoError(t, err)
		})
	})
	t.Run("CORS", func(t *testing.T) {
		t.Run("strict mode", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"test.nl"}
			instance, _, err := createEchoServer(cfg, nil, true, true)
			assert.NotNil(t, instance)
			assert.NoError(t, err)
		})
		t.Run("strict mode - wildcard not allowed", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"*"}
			instance, _, err := createEchoServer(cfg, nil, true, true)
			assert.Nil(t, instance)
			assert.EqualError(t, err, "wildcard CORS origin is not allowed in strict mode")
		})
		t.Run("lenient mode", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"*"}
			instance, _, err := createEchoServer(cfg, nil, false, true)
			assert.NotNil(t, instance)
			assert.NoError(t, err)
		})
	})

}

func Test_skipLogRequest(t *testing.T) {
	req := &http.Request{}
	ctx := echo.New().NewContext(req, nil)
	t.Run("matches", func(t *testing.T) {
		req.RequestURI = "/status"
		assert.True(t, skipLogRequest(ctx))
		req.RequestURI = "/metrics"
		assert.True(t, skipLogRequest(ctx))
	})
	t.Run("no match", func(t *testing.T) {
		req.RequestURI = "/status/"
		assert.False(t, skipLogRequest(ctx))
		req.RequestURI = "/status/foo"
		assert.False(t, skipLogRequest(ctx))
		req.RequestURI = "/foobar"
		assert.False(t, skipLogRequest(ctx))
	})
}

func Test_loggerMiddleware(t *testing.T) {
	t.Run("it logs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		response := &echo.Response{}
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().NoContent(http.StatusNoContent).Do(func(status int) { response.Status = status })
		echoMock.EXPECT().Request().Return(&http.Request{RequestURI: "/test"})
		echoMock.EXPECT().Response().Return(response)
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		err := logFunc(func(context echo.Context) error {
			return context.NoContent(http.StatusNoContent)
		})(echoMock)

		assert.NoError(t, err)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, "::1", hook.LastEntry().Data["remote_ip"])
		assert.Equal(t, http.StatusNoContent, hook.LastEntry().Data["status"])
		assert.Equal(t, "/test", hook.LastEntry().Data["uri"])
		ctrl.Finish()
	})

	t.Run("it handles echo.HTTPErrors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return echo.NewHTTPError(http.StatusForbidden)
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusForbidden, hook.LastEntry().Data["status"])
		ctrl.Finish()

	})

	t.Run("it handles httpStatusCodeError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return NotFoundError("not found")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusNotFound, hook.LastEntry().Data["status"])
		ctrl.Finish()
	})

	t.Run("it handles go errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return errors.New("failed")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusInternalServerError, hook.LastEntry().Data["status"])
		ctrl.Finish()
	})
}

func TestNewInternalRateLimiter(t *testing.T) {
	t.Run("it works", func(t *testing.T) {
		e := echo.New()
		rlMiddleware := NewInternalRateLimiter(map[string][]string{http.MethodPost: {"/foo"}}, time.Minute, 30, 2)

		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		testcases := []struct {
			method            string
			expectedStatus    int
			waitBeforeRequest time.Duration
			path              string
		}{
			{http.MethodPost, http.StatusOK, 0, "/foo"},               // first request in burst
			{http.MethodPost, http.StatusOK, 0, "/foo"},               // second request in burst
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // bucket empty
			{http.MethodPost, http.StatusOK, 0, "/other"},             // unprotected path should still work
			{http.MethodGet, http.StatusOK, 0, "/foo"},                // other method same path should still work
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // check bucket still empty
			{http.MethodPost, http.StatusOK, 2 * time.Second, "/foo"}, // wait 2 seconds to refill bucket
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // bucket empty again
		}

		for _, testcase := range testcases {
			time.Sleep(testcase.waitBeforeRequest)
			req := httptest.NewRequest(testcase.method, testcase.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath(testcase.path)
			_ = rlMiddleware(handler)(c)
			assert.Equalf(t, testcase.expectedStatus, rec.Code, "unexpected HTTP response for %s on %s", testcase.method, testcase.path)
		}
	})

}
