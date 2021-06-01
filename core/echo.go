package core

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"schneider.vip/problem"
	"strings"
	"sync"
)

// EchoServer implements both the EchoRouter interface and Start function to aid testing.
type EchoServer interface {
	EchoRouter
	Start(address string) error
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route
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

func createEchoServer(cfg HTTPConfig, strictmode bool) (EchoServer, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true
	// Register Echo logger middleware but do not log calls to the status endpoint,
	// since that gets called by the Docker healthcheck very, very often which leads to lots of clutter in the log.
	loggerConfig := middleware.DefaultLoggerConfig
	loggerConfig.Skipper = requestsStatusEndpoint
	echoServer.Use(middleware.LoggerWithConfig(loggerConfig))
	echoServer.HTTPErrorHandler = httpErrorHandler
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
	echoServer.Use(DecodeURIPath)
	return echoServer, nil
}

func requestsStatusEndpoint(context echo.Context) bool {
	return context.Request().RequestURI == "/status"
}

func httpErrorHandler(err error, ctx echo.Context) {
	if prb, ok := err.(*problem.Problem); ok {
		if !ctx.Response().Committed {
			if _, err := prb.WriteTo(ctx.Response()); err != nil {
				ctx.Echo().Logger.Error(err)
			}
		}
	} else {
		ctx.Echo().DefaultHTTPErrorHandler(err, ctx)
	}
}

// NewProblem creates a new problem.Problem
func NewProblem(title string, status int, detail string) *problem.Problem {
	return problem.New(problem.Title(title), problem.Status(status), problem.Detail(detail))
}
