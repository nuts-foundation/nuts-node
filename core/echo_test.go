package core

import (
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
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

func Test_MultiEcho_Routes(t *testing.T) {
	t.Run("right HTTP methods are mapped", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		s := NewMockEchoServer(ctrl)
		s.EXPECT().PATCH("patch", nil)
		s.EXPECT().GET("get", nil)
		s.EXPECT().OPTIONS("options", nil)
		s.EXPECT().HEAD("head", nil)
		s.EXPECT().DELETE("delete", nil)
		s.EXPECT().POST("post", nil)
		s.EXPECT().PUT("put", nil)
		s.EXPECT().TRACE("trace", nil)
		s.EXPECT().CONNECT("connect", nil)

		m := NewMultiEcho(func() EchoServer {
			return s
		}, NewServerConfig().HTTP.HTTPConfig)
		m.PATCH("patch", nil)
		m.GET("get", nil)
		m.OPTIONS("options", nil)
		m.HEAD("head", nil)
		m.DELETE("delete", nil)
		m.POST("post", nil)
		m.PUT("put", nil)
		m.TRACE("trace", nil)
		m.CONNECT("connect", nil)
	})

}

func Test_MultiEcho(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defaultHttpCfg := NewServerConfig().HTTP.HTTPConfig

	// Set up expected echo servers
	defaultServer := NewMockEchoServer(ctrl)
	defaultServer.EXPECT().PATCH("/other/default-endpoint", gomock.Any())
	defaultServer.EXPECT().Start(defaultHttpCfg.Address)

	internalServer := NewMockEchoServer(ctrl)
	internalServer.EXPECT().GET("/internal/internal-endpoint", gomock.Any())
	internalServer.EXPECT().Start("internal:8080")

	publicServer := NewMockEchoServer(ctrl)
	publicServer.EXPECT().POST("/public/pub-endpoint", gomock.Any())
	publicServer.EXPECT().DELETE("/extra-public/extra-pub-endpoint", gomock.Any())
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

	m.POST("/public/pub-endpoint", nil)
	m.DELETE("/extra-public/extra-pub-endpoint", nil)
	m.GET("/internal/internal-endpoint", nil)
	m.PATCH("/other/default-endpoint", nil)

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
