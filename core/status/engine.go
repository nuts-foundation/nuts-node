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

package status

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/labstack/echo/v4"
)

const moduleName = "Status"
const diagnosticsEndpoint = "/status/diagnostics"
const statusEndpoint = "/status"
const checkHealthEndpoint = "/health"

type status struct {
	system    *core.System
	startTime time.Time
}

// NewStatusEngine creates a new Engine for viewing all engines
func NewStatusEngine(system *core.System) core.Engine {
	return &status{
		system:    system,
		startTime: time.Now(),
	}
}

func (s *status) Name() string {
	return moduleName
}

func (s *status) Routes(router core.EchoRouter) {
	router.Add(http.MethodGet, diagnosticsEndpoint, s.diagnosticsOverview)
	router.Add(http.MethodGet, statusEndpoint, statusOK)
	router.Add(http.MethodGet, checkHealthEndpoint, s.checkHealth)
}

func (s *status) diagnosticsOverview(ctx echo.Context) error {
	diagnostics := s.collectDiagnostics()
	hdr := ctx.Request().Header.Get("Accept")
	if strings.HasPrefix(hdr, "application/json") {
		return ctx.JSON(http.StatusOK, s.diagnosticsSummaryAsMap(diagnostics))
	}
	// Return as YAML but serve as text/plain, because we always allowed easy diagnostics viewing through the browser.
	// When serving it as application/yaml, it is downloaded by the browser instead of rendered directly, so only set header if requested.
	if strings.HasPrefix(hdr, "application/yaml") {
		ctx.Response().Header().Set("Content-Type", "application/yaml")
	}
	return ctx.String(http.StatusOK, s.diagnosticsSummaryAsYAML(diagnostics))
}

func (s *status) diagnosticsSummaryAsYAML(diagnostics map[string][]core.DiagnosticResult) string {
	buf := new(bytes.Buffer)
	encoder := yaml.NewEncoder(buf)
	_ = encoder.Encode(s.diagnosticsSummaryAsMap(diagnostics))
	return buf.String()
}

func (s *status) diagnosticsSummaryAsMap(diagnostics map[string][]core.DiagnosticResult) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})
	for engine, results := range diagnostics {
		engineResults := make(map[string]interface{}, 0)
		for _, curr := range results {
			engineResults[curr.Name()] = curr.Result()
		}
		result[engine] = engineResults
	}
	return result
}

// Diagnostics returns list of DiagnosticResult for the StatusEngine.
// The results are a list of all registered engines
func (s *status) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{
		&core.GenericDiagnosticResult{Title: "uptime", Outcome: time.Since(s.startTime).Truncate(time.Second)},
		&core.GenericDiagnosticResult{Title: "software_version", Outcome: core.Version()},
		&core.GenericDiagnosticResult{Title: "git_commit", Outcome: core.GitCommit},
		&core.GenericDiagnosticResult{Title: "os_arch", Outcome: core.OSArch()},
	}
}

func (s *status) collectDiagnostics() map[string][]core.DiagnosticResult {
	result := make(map[string][]core.DiagnosticResult, 0)
	s.system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.ViewableDiagnostics); ok {
			result[strings.ToLower(m.Name())] = m.Diagnostics()
		}
	})
	return result
}

func (s *status) checkHealth(ctx echo.Context) error {
	result := s.doCheckHealth()
	responseCode := 200
	// log all non-healthy components
	if result.Status != core.HealthStatusUp {
		var failures []string
		for component, componentHealth := range result.Details.(map[string]core.Health) {
			if componentHealth.Status != core.HealthStatusUp {
				failures = append(failures, fmt.Sprintf(" - %s: %v", component, componentHealth.Details))
			}
		}
		logrus.Warnf("Health check status is not UP, failing components:\n%s", strings.Join(failures, "\n"))
	}
	// return 503 only when status is core.HealthStatusDown.
	// core.HealthStatusUnknown should return 200, or it would fail with load balancers and container orchestrators
	if result.Status == core.HealthStatusDown {
		responseCode = 503
	}

	return ctx.JSON(responseCode, result)
}

func (s *status) doCheckHealth() core.Health {
	results := make(map[string]core.Health, 0)
	s.system.VisitEngines(func(engine core.Engine) {
		checker, ok := engine.(core.HealthCheckable)
		if ok {
			for name, result := range checker.CheckHealth() {
				results[strings.ToLower(checker.Name()+"."+name)] = result
			}
		}
	})

	// Overall status is derived from the performed checks. The most severe status is returned (UP < UNKNOWN < DOWN).
	overallStatus := core.HealthStatusUp
	for _, result := range results {
		if result.Status.Severity() > overallStatus.Severity() {
			overallStatus = result.Status
		}
	}
	result := core.Health{
		Status:  overallStatus,
		Details: results,
	}
	return result
}

// statusOK returns 200 OK with an "OK" body
func statusOK(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}
