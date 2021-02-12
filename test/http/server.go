package http

import "github.com/labstack/echo/v4"

type StubEchoServer struct {
	BoundAddress string
}

func (s StubEchoServer) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	return nil
}

func (s *StubEchoServer) Start(address string) error {
	s.BoundAddress = address
	return nil
}
