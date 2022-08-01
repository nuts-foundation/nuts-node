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
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
)

// EchoServer implements both the EchoRouter interface and Start function to aid testing.
type EchoServer interface {
	EchoRouter
	Start(address string) error
	Shutdown(ctx context.Context) error
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route

	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route

	Use(middleware ...echo.MiddlewareFunc)
}

const defaultEchoGroup = ""

// NewMultiEcho creates a new MultiEcho which uses the given function to create EchoServers. If a route is registered
// for an unknown group is is bound to the given defaultInterface.
func NewMultiEcho(creatorFn func(cfg HTTPConfig) (EchoServer, error), defaultInterface HTTPConfig) *MultiEcho {
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
	creatorFn  func(cfg HTTPConfig) (EchoServer, error)
}

// CONNECT registers a new CONNECT route for the given path with optional middleware.
func (c *MultiEcho) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodConnect, path, h, m...)
}

// DELETE registers a new DELETE route for the given path with optional middleware.
func (c *MultiEcho) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodDelete, path, h, m...)
}

// GET registers a new GET route for the given path with optional middleware.
func (c *MultiEcho) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodGet, path, h, m...)
}

// HEAD registers a new HEAD route for the given path with optional middleware.
func (c *MultiEcho) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodHead, path, h, m...)
}

// OPTIONS registers a new OPTIONS route for the given path with optional middleware.
func (c *MultiEcho) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodOptions, path, h, m...)
}

// PATCH registers a new PATCH route for the given path with optional middleware.
func (c *MultiEcho) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPatch, path, h, m...)
}

// POST registers a new POST route for the given path with optional middleware.
func (c *MultiEcho) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPost, path, h, m...)
}

// PUT registers a new PUT route for the given path with optional middleware.
func (c *MultiEcho) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPut, path, h, m...)
}

// TRACE registers a new TRACE route for the given path with optional middleware.
func (c *MultiEcho) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodTrace, path, h, m...)
}

// Add adds a route to the Echo server.
func (c *MultiEcho) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	group := getGroup(path)
	groupAddress := c.groups[group]
	var iface EchoServer
	if groupAddress != "" {
		iface = c.interfaces[groupAddress]
	} else {
		iface = c.interfaces[c.groups[defaultEchoGroup]]
	}
	return iface.Add(method, path, handler, middleware...)
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
		server, err := c.creatorFn(interfaceConfig)
		if err != nil {
			return err
		}
		c.interfaces[interfaceConfig.Address] = server
	}
	return nil
}

// Start starts all Echo servers.
func (c MultiEcho) Start() error {
	wg := &sync.WaitGroup{}
	wg.Add(len(c.interfaces))
	errChan := make(chan error, len(c.interfaces))
	for address, echoServer := range c.interfaces {
		c.start(address, echoServer, wg, errChan)
	}
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}
	return nil
}

// Shutdown stops all Echo servers.
func (c MultiEcho) Shutdown() {
	for address, echoServer := range c.interfaces {
		logrus.Tracef("Stopping interface: %s", address)
		if err := echoServer.Shutdown(context.Background()); err != nil {
			logrus.Errorf("Unable to shutdown interface (address=%s): %v", address, err)
		}
	}
}

// Use applies the given middleware function to all Echo servers.
func (c MultiEcho) Use(middleware ...echo.MiddlewareFunc) {
	for _, curr := range c.interfaces {
		curr.Use(middleware...)
	}
}

func (c *MultiEcho) start(address string, server EchoServer, wg *sync.WaitGroup, errChan chan error) {
	go func() {
		if err := server.Start(address); err != nil {
			errChan <- err
		}
		wg.Done()
	}()
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

var _logger = logrus.StandardLogger().WithField("module", "http-server")

// Logger returns a logger which should be used for logging in this engine. It adds fields so
// log entries from this engine can be recognized as such.
func Logger() *logrus.Entry {
	return _logger
}

// loggerConfig Contains the configuration for the loggerMiddleware.
// Currently, this only allows for configuration of skip paths
type loggerConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper
	logger  *logrus.Entry
}

// loggerMiddleware Is a custom logger middleware.
// Should be added as the outer middleware to catch all errors and potential status rewrites
// The current RequestLogger is not usable with our custom problem errors.
// See https://github.com/labstack/echo/issues/2015
func loggerMiddleware(config loggerConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			if config.Skipper != nil && config.Skipper(c) {
				return next(c)
			}
			err = next(c)
			req := c.Request()
			res := c.Response()

			status := res.Status
			if err != nil {
				switch errWithStatus := err.(type) {
				case *echo.HTTPError:
					status = errWithStatus.Code
				case httpStatusCodeError:
					status = errWithStatus.statusCode
				default:
					status = http.StatusInternalServerError
				}
			}

			config.logger.WithFields(logrus.Fields{
				"remote_ip": c.RealIP(),
				"method":    req.Method,
				"uri":       req.RequestURI,
				"status":    status,
			}).Info("request")
			return
		}
	}
}

func createEchoServer(cfg HTTPConfig, strictmode bool) (*echo.Echo, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true

	// ErrorHandler
	echoServer.HTTPErrorHandler = createHTTPErrorHandler()

	// Reverse proxies must set the X-Forwarded-For header to the original client IP.
	echoServer.IPExtractor = echo.ExtractIPFromXFFHeader()

	// CORS Configuration
	if cfg.CORS.Enabled() {
		if strictmode {
			for _, origin := range cfg.CORS.Origin {
				if strings.TrimSpace(origin) == "*" {
					return nil, errors.New("wildcard CORS origin is not allowed in strict mode")
				}
			}
		}
		echoServer.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: cfg.CORS.Origin}))
	}

	// Use middleware to decode URL encoded path parameters like did%3Anuts%3A123 -> did:nuts:123
	echoServer.Use(DecodeURIPath)

	echoServer.Use(loggerMiddleware(loggerConfig{Skipper: requestsStatusEndpoint, logger: Logger()}))

	return echoServer, nil
}

func requestsStatusEndpoint(context echo.Context) bool {
	return context.Request().RequestURI == "/status"
}
