package core

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"strings"
)

// EchoServer implements both the EchoRouter interface and Start function to aid testing.
type EchoServer interface {
	EchoRouter
	Start(address string) error
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

const defaultEchoGroup = ""

// NewMultiEcho creates a new MultiEcho which uses the given function to create EchoServers. If a route is registered
// for an unknown group is is bound to the given defaultInterface.
func NewMultiEcho(creatorFn func() EchoServer, defaultInterface HTTPConfig) *MultiEcho {
	instance := &MultiEcho{
		interfaces: map[string]EchoServer{},
		groups:     map[string]string{},
		creatorFn:  creatorFn,
	}
	_ = instance.Bind(defaultEchoGroup, defaultInterface)
	return instance
}

// MultiEcho allows to bind specific URLs to specific HTTP interfaces
type MultiEcho struct {
	interfaces map[string]EchoServer
	groups     map[string]string
	creatorFn  func() EchoServer
}

// Bind binds the given group (first part of the URL) to the given HTTP interface. Calling Bind for the same group twice
// results in an error being returned.
func (c *MultiEcho) Bind(group string, interfaceConfig HTTPConfig) error {
	normGroup := strings.ToLower(group)
	if _, groupExists := c.groups[normGroup]; groupExists {
		return fmt.Errorf("http bind group already exists: %s", group)
	}
	c.groups[group] = interfaceConfig.Address
	if _, addressBound := c.interfaces[interfaceConfig.Address]; !addressBound {
		c.interfaces[interfaceConfig.Address] = c.creatorFn()
	}
	return nil
}

// Start starts all Echo servers.
func (c MultiEcho) Start() error {
	for address, echoServer := range c.interfaces {
		if err := echoServer.Start(address); err != nil {
			return err
		}
	}
	return nil
}

func (c *MultiEcho) register(path string, registerFn func(router EchoRouter) *echo.Route) {
	group := getGroup(path)
	groupAddress := c.groups[group]
	if groupAddress != "" {
		registerFn(c.interfaces[groupAddress])
	} else {
		registerFn(c.interfaces[c.groups[defaultEchoGroup]])
	}
}

func (c MultiEcho) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.CONNECT(path, h, m...)
	})
	return nil
}

func (c MultiEcho) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.DELETE(path, h, m...)
	})
	return nil
}

func (c MultiEcho) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.GET(path, h, m...)
	})
	return nil
}

func (c MultiEcho) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.HEAD(path, h, m...)
	})
	return nil
}

func (c MultiEcho) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.OPTIONS(path, h, m...)
	})
	return nil
}

func (c MultiEcho) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.PATCH(path, h, m...)
	})
	return nil
}

func (c MultiEcho) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.POST(path, h, m...)
	})
	return nil
}

func (c MultiEcho) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.PUT(path, h, m...)
	})
	return nil
}

func (c MultiEcho) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	c.register(path, func(router EchoRouter) *echo.Route {
		return router.TRACE(path, h, m...)
	})
	return nil
}

func getGroup(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			return strings.ToLower(part)
		}
	}
	return ""
}
