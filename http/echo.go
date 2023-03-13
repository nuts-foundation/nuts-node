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
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/sirupsen/logrus"
)

// RootPath is the path used for routes that don't map to a configured bind.
const RootPath = "/"

// EchoCreator is a function used to create an Echo server.
type EchoCreator func() (EchoServer, error)

// NewMultiEcho creates a new MultiEcho which uses the given function to create core.EchoServers. If a route is registered
// for an unknown path is bound to the given defaultInterface.
func NewMultiEcho() *MultiEcho {
	instance := &MultiEcho{
		interfaces: map[string]EchoServer{},
		binds:      map[string]string{},
	}

	// Add adds a route to the Echo server.
	instance.echoAdapter.useFn = instance.Use
	instance.echoAdapter.addFn = func(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
		bind := instance.getBindFromPath(path)
		bindAddress := instance.binds[bind]
		var iface EchoServer
		if bindAddress != "" {
			iface = instance.interfaces[bindAddress]
		} else {
			iface = instance.interfaces[instance.binds[RootPath]]
		}
		return iface.Add(method, path, handler, middleware...)
	}
	return instance
}

// MultiEcho allows to bind specific URLs to specific HTTP interfaces
type MultiEcho struct {
	echoAdapter

	interfaces map[string]EchoServer
	binds      map[string]string
}

// Bind binds the given path (first part of the URL) to the given HTTP interface. Calling Bind for the same path twice
// results in an error being returned.
// If address wasn't used for another bind and thus leads to creating a new Echo server, it returns true.
// If an existing Echo server is returned, it returns false.
func (c *MultiEcho) Bind(path string, address string, creatorFn func() (EchoServer, error)) error {
	if len(address) == 0 {
		return errors.New("empty address")
	}
	err := c.validateBindPath(path)
	if err != nil {
		return err
	}
	path = c.getBindFromPath(path)
	if _, pathExists := c.binds[path]; pathExists {
		return fmt.Errorf("http bind already exists: %s", path)
	}
	c.binds[path] = address
	if _, addressBound := c.interfaces[address]; !addressBound {
		server, err := creatorFn()
		if err != nil {
			return err
		}
		c.interfaces[address] = server
	}
	return nil
}

// Start starts all Echo servers.
func (c MultiEcho) Start() error {
	wg := &sync.WaitGroup{}
	wg.Add(len(c.interfaces))
	errChan := make(chan error, len(c.interfaces))
	for addr, curr := range c.interfaces {
		go func(addr string, server EchoServer) {
			if err := server.Start(addr); err != nil {
				errChan <- err
			}
			wg.Done()
		}(addr, curr)
	}
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}
	return nil
}

// Shutdown stops all Echo servers.
func (c MultiEcho) Shutdown(ctx context.Context) error {
	var result error
	for address, curr := range c.interfaces {
		logrus.Tracef("Stopping interface: %s", address)
		if err := curr.Shutdown(ctx); err != nil {
			logrus.
				WithError(err).
				Errorf("Unable to shutdown interface: %s", address)
			result = errors.New("one or more HTTP interfaces failed to shutdown")
		}
	}
	return result
}

// Use applies the given middleware function to all Echo servers.
func (c MultiEcho) Use(middleware ...echo.MiddlewareFunc) {
	for _, curr := range c.interfaces {
		curr.Use(middleware...)
	}
}

func (c *MultiEcho) getInterface(path string) EchoServer {
	bind := c.getBindFromPath(path)
	return c.interfaces[c.binds[bind]]
}

func (c *MultiEcho) getAddressForPath(path string) string {
	return c.binds[c.getBindFromPath(path)]
}

func (c *MultiEcho) validateBindPath(path string) error {
	path = strings.Trim(path, "/")
	if strings.Contains(path, "/") {
		return fmt.Errorf("bind can't contain subpaths: %s", path)
	}
	return nil
}

func (c *MultiEcho) getBindFromPath(path string) string {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		path = RootPath
	} else {
		path = "/" + strings.ToLower(parts[0])
	}
	return path
}

// EchoServer implements both the EchoRouter interface and Start function to aid testing.
type EchoServer interface {
	core.EchoRouter
	Start(address string) error
	Shutdown(ctx context.Context) error
}

var _ core.EchoRouter = (*echoAdapter)(nil)

type echoAdapter struct {
	core.EchoRouter
	EchoServer

	startFn    func(address string) error
	shutdownFn func(ctx context.Context) error
	addFn      func(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route
	useFn      func(middleware ...echo.MiddlewareFunc)
}

// Start calls the start function.
func (c *echoAdapter) Start(address string) error {
	return c.startFn(address)
}

// Shutdown calls the shutdown function.
func (c *echoAdapter) Shutdown(ctx context.Context) error {
	return c.shutdownFn(ctx)
}

// Use calls the use function.
func (c *echoAdapter) Use(middleware ...echo.MiddlewareFunc) {
	c.useFn(middleware...)
}

// Add calls the add function.
func (c *echoAdapter) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	return c.addFn(method, path, handler, middleware...)
}

// CONNECT registers a new CONNECT route for the given path with optional middleware.
func (c *echoAdapter) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodConnect, path, h, m...)
}

// DELETE registers a new DELETE route for the given path with optional middleware.
func (c *echoAdapter) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodDelete, path, h, m...)
}

// GET registers a new GET route for the given path with optional middleware.
func (c *echoAdapter) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodGet, path, h, m...)
}

// HEAD registers a new HEAD route for the given path with optional middleware.
func (c *echoAdapter) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodHead, path, h, m...)
}

// OPTIONS registers a new OPTIONS route for the given path with optional middleware.
func (c *echoAdapter) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodOptions, path, h, m...)
}

// PATCH registers a new PATCH route for the given path with optional middleware.
func (c *echoAdapter) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPatch, path, h, m...)
}

// POST registers a new POST route for the given path with optional middleware.
func (c *echoAdapter) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPost, path, h, m...)
}

// PUT registers a new PUT route for the given path with optional middleware.
func (c *echoAdapter) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodPut, path, h, m...)
}

// TRACE registers a new TRACE route for the given path with optional middleware.
func (c *echoAdapter) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return c.Add(http.MethodTrace, path, h, m...)
}
