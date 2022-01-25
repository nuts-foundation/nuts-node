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
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsEngine = "Metrics"

// NewMetricsEngine creates a new Engine for exposing prometheus metrics via http.
// Metrics are exposed on /metrics, by default the GoCollector and ProcessCollector are enabled.
func NewMetricsEngine() Engine {
	return &metrics{}
}

type metrics struct{}

func (e *metrics) Name() string {
	return metricsEngine
}

func (e *metrics) Routes(router EchoRouter) {
	router.Add(http.MethodGet, "/metrics", echo.WrapHandler(promhttp.Handler()))
}

// Configure configures the MetricsEngine.
// It configures and registers the prometheus collector
func (*metrics) Configure(_ ServerConfig) error {
	prometheusCollectors := []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	}

	are := prometheus.AlreadyRegisteredError{}

	for _, c := range prometheusCollectors {
		if err := prometheus.Register(c); err != nil && err.Error() != are.Error() {
			return err
		}
	}

	return nil
}
