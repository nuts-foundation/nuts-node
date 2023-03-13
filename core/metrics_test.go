/*
 * Nuts node
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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMetricsEngine_Name(t *testing.T) {
	named := NewMetricsEngine().(Named)
	assert.Equal(t, "Metrics", named.Name())
}

func TestNewMetricsEngine_Metrics(t *testing.T) {
	engine := NewMetricsEngine().(*metrics)
	_ = engine.Configure(*NewServerConfig())
	defer func(engine *metrics) {
		_ = engine.Shutdown()
	}(engine)
	e := echo.New()
	engine.Routes(e)

	requestPath := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(rec.Result().Body)
		bodyBytes, _ := io.ReadAll(rec.Result().Body)
		return string(bodyBytes)
	}
	requestMetrics := func() string {
		return requestPath("/metrics")
	}

	t.Run("go process metrics", func(t *testing.T) {
		response := requestMetrics()

		assert.Contains(t, response, "go_goroutines")
		assert.Contains(t, response, "go_memstats")
		assert.Contains(t, response, "go_threads")
	})

	t.Run("promhttp metrics", func(t *testing.T) {
		response := requestMetrics()

		assert.Contains(t, response, "promhttp_metric_handler_requests_in_flight")
	})

}

func TestMetricsEngine_Lifecycle(t *testing.T) {
	t.Run("shutdown unregisters metrics", func(t *testing.T) {
		engine := NewMetricsEngine().(*metrics)
		_ = engine.Configure(*NewServerConfig())

		e := echo.New()
		engine.Routes(e)

		err := engine.Shutdown()
		assert.NoError(t, err)

		// Assert we can register previously registered metrics, which indicates they were unregistered by Shutdown()
		assert.NoError(t, prometheus.Register(collectors.NewGoCollector()))
	})
	t.Run("calling configure twice is ok", func(t *testing.T) {
		engine := NewMetricsEngine().(*metrics)
		defer func(engine *metrics) {
			_ = engine.Shutdown()
		}(engine)
		err := engine.Configure(*NewServerConfig())

		assert.NoError(t, err)
	})
}
