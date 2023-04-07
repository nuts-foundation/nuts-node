package http

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func StartEchoServer(t *testing.T, registerRoutesFunc func(router core.EchoRouter)) string {
	httpPort := test.FreeTCPPort()
	httpServer := echo.New()
	httpServer.Use(middleware.Logger())
	t.Cleanup(func() {
		httpServer.Close()
	})
	registerRoutesFunc(httpServer)
	startErrorChannel := make(chan error)
	go func() {
		err := httpServer.Start(":" + strconv.Itoa(httpPort))
		if err != nil && err != http.ErrServerClosed {
			startErrorChannel <- err
		}
	}()

	httpServerURL := fmt.Sprintf("http://localhost:%d", httpPort)

	test.WaitFor(t, func() (bool, error) {
		// Check if Start() error-ed
		if len(startErrorChannel) > 0 {
			return false, <-startErrorChannel
		}
		_, err := http.Get(httpServerURL)
		return err == nil, nil
	}, 5*time.Second, "time-out waiting for HTTP server to start")

	return httpServerURL
}
