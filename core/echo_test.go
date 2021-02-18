package core

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func Test_MultiEcho_Bind(t *testing.T) {
	t.Run("group already bound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := NewServerConfig().HTTP.HTTPConfig
		m := NewMultiEcho(func() EchoServer {
			return NewMockEchoServer(ctrl)
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
		m := NewMultiEcho(func() EchoServer {
			server := NewMockEchoServer(ctrl)
			server.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("unable to start"))
			return server
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
	createFn := func() EchoServer {
		servers := []EchoServer{defaultServer, internalServer, publicServer}
		s := servers[createFnCalled]
		createFnCalled++
		return s
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
