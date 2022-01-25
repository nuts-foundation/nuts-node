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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/labstack/echo/v4"
)

const moduleName = "Status"
const diagnosticsEndpoint = "/status/diagnostics"
const statusEndpoint = "/status"

type status struct {
	system    *core.System
	startTime time.Time
}

//NewStatusEngine creates a new Engine for viewing all engines
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
}

func (s *status) diagnosticsOverview(ctx echo.Context) error {
	diagnostics := s.collectDiagnostics()
	hdr := ctx.Request().Header.Get("Accept")
	if strings.HasPrefix(hdr, "application/json") {
		return ctx.JSON(http.StatusOK, s.diagnosticsSummaryAsMap(diagnostics))
	}
	return ctx.String(http.StatusOK, s.diagnosticsSummaryAsText(diagnostics))
}

func (s *status) diagnosticsSummaryAsText(diagnostics map[string][]core.DiagnosticResult) string {
	var lines []string
	// Re-loop over engines to retain order
	s.system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.ViewableDiagnostics); ok {
			lcName := strings.ToLower(strings.ToLower(m.Name()))
			lines = append(lines, lcName)
			for _, d := range diagnostics[lcName] {
				lines = append(lines, fmt.Sprintf("\t%s: %s", d.Name(), d.String()))
			}
		}
	})
	return strings.Join(lines, "\n")
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
		&core.GenericDiagnosticResult{Title: "engines", Outcome: s.listAllEngines()},
		&core.GenericDiagnosticResult{Title: "uptime", Outcome: time.Now().Sub(s.startTime).Truncate(time.Second)},
		&core.GenericDiagnosticResult{Title: "software_version", Outcome: core.Version()},
		&core.GenericDiagnosticResult{Title: "git_commit", Outcome: core.GitCommit},
		&core.GenericDiagnosticResult{Title: "os_arch", Outcome: core.OSArch()},
	}
}

func (s *status) listAllEngines() []string {
	var names []string
	s.system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.Named); ok {
			names = append(names, m.Name())
		}
	})
	return names
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

// statusOK returns 200 OK with an "OK" body
func statusOK(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}
