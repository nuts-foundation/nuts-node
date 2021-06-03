package core

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func Test_MultiEcho_Bind(t *testing.T) {
	t.Run("group already bound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := NewServerConfig().HTTP.HTTPConfig
		m := NewMultiEcho(func(_ HTTPConfig) (EchoServer, error) {
			return NewMockEchoServer(ctrl), nil
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
		m := NewMultiEcho(func(_ HTTPConfig) (EchoServer, error) {
			server := NewMockEchoServer(ctrl)
			server.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("unable to start"))
			return server, nil
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
	createFn := func(_ HTTPConfig) (EchoServer, error) {
		servers := []EchoServer{defaultServer, internalServer, publicServer}
		s := servers[createFnCalled]
		createFnCalled++
		return s, nil
	}

	// Bind interfaces
	m := NewMultiEcho(createFn, defaultHttpCfg)
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

func Test_getGroup(t *testing.T) {
	assert.Equal(t, "internal", getGroup("/internal/vdr/v1/did"))
	assert.Equal(t, "internal", getGroup("/internal"))
	assert.Equal(t, "internal", getGroup("internal"))
	assert.Equal(t, "internal", getGroup("internal/"))
	assert.Equal(t, "", getGroup(""))
	assert.Equal(t, "", getGroup("/"))
}

func Test_createEchoServer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		instance, err := createEchoServer(NewServerConfig().HTTP.HTTPConfig, true, nil)
		assert.NotNil(t, instance)
		assert.NoError(t, err)
	})
	t.Run("CORS", func(t *testing.T) {
		t.Run("strict mode", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"test.nl"}
			instance, err := createEchoServer(cfg, true, nil)
			assert.NotNil(t, instance)
			assert.NoError(t, err)
		})
		t.Run("strict mode - wildcard not allowed", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"*"}
			instance, err := createEchoServer(cfg, true, nil)
			assert.Nil(t, instance)
			assert.EqualError(t, err, "wildcard CORS origin is not allowed in strict mode")
		})
		t.Run("lenient mode", func(t *testing.T) {
			cfg := NewServerConfig().HTTP.HTTPConfig
			cfg.CORS.Origin = []string{"*"}
			instance, err := createEchoServer(cfg, false, nil)
			assert.NotNil(t, instance)
			assert.NoError(t, err)
		})
	})

}

func Test_requestsStatusEndpoint(t *testing.T) {
	req := &http.Request{}
	ctx := echo.New().NewContext(req, nil)
	t.Run("matches", func(t *testing.T) {
		req.RequestURI = "/status"
		assert.True(t, requestsStatusEndpoint(ctx))
	})
	t.Run("no match", func(t *testing.T) {
		req.RequestURI = "/status/"
		assert.False(t, requestsStatusEndpoint(ctx))
		req.RequestURI = "/status/foo"
		assert.False(t, requestsStatusEndpoint(ctx))
		req.RequestURI = "/foobar"
		assert.False(t, requestsStatusEndpoint(ctx))
	})
}
