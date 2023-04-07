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
	"github.com/labstack/echo/v4"
)

type StubEchoServer struct {
	BoundAddress string
}

func (s StubEchoServer) Use(middleware ...echo.MiddlewareFunc) {
}

func (s StubEchoServer) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	panic("implement me")
}

func (s StubEchoServer) Shutdown(ctx context.Context) error {
	return nil
}

func (s StubEchoServer) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	return nil
}

func (s *StubEchoServer) Start(address string) error {
	s.BoundAddress = address
	return nil
}
