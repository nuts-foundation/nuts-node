/*
 * Copyright (C) 2023 Nuts community
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
