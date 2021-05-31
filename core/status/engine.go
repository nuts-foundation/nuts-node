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
	"encoding/json"
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

type diagnosticsRenderer func(map[string][]core.DiagnosticResult, echo.Context) error

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
	router.Add(http.MethodGet, diagnosticsEndpoint, s.handleGetDiagnostics)
	router.Add(http.MethodGet, statusEndpoint, handleGetStatus)
}

func (s *status) handleGetDiagnostics(ctx echo.Context) error {
	requestedContentType := ctx.Request().Header.Get("Accept")
	renderer := getRenderer(requestedContentType)
	return renderer(s.collectDiagnostics(), ctx)
}

func (s *status) collectDiagnostics() map[string][]core.DiagnosticResult {
	result := make(map[string][]core.DiagnosticResult, 0)
	s.system.VisitEngines(func(engine core.Engine) {
		if m, ok := engine.(core.ViewableDiagnostics); ok {
			result[m.Name()] = append(result[m.Name()], m.Diagnostics()...)
		}
	})
	return result
}

// Diagnostics returns list of DiagnosticResult for the StatusEngine.
// The results are a list of all registered engines
func (s *status) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{
		&core.GenericDiagnosticResult{Title: "Registered engines", Value: s.listAllEngines()},
		&core.GenericDiagnosticResult{Title: "Uptime", Value: time.Now().Sub(s.startTime).String()},
		&core.GenericDiagnosticResult{Title: "Version", Value: core.Version()},
		&core.GenericDiagnosticResult{Title: "Git commit", Value: core.GitCommit},
		&core.GenericDiagnosticResult{Title: "OS/Arch", Value: core.OSArch()},
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

// handleGetStatus returns 200 OK with a "OK" body
func handleGetStatus(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}

func renderAsText(engineDiagnostics map[string][]core.DiagnosticResult, ctx echo.Context) error {
	var lines []string
	for engine, items := range engineDiagnostics {
		lines = append(lines, engine)
		for _, item := range items {
			lines = append(lines, fmt.Sprintf("\t%s: %s", item.Name(), item.String()))
		}
	}
	return ctx.String(http.StatusOK, strings.Join(lines, "\n"))
}

func renderAsJSON(engineDiagnostics map[string][]core.DiagnosticResult, ctx echo.Context) error {
	result := make(map[string]map[string]interface{}, 0)
	for engineName, entries := range engineDiagnostics {
		asMap := make(map[string]interface{}, 0)
		for _, diagnosticResult := range entries {
			asMap[diagnosticResult.Name()] = toJSONValue(diagnosticResult)
		}
		result[engineName] = asMap
	}
	return ctx.JSONPretty(http.StatusOK, result, "  ")
}

func toJSONValue(element core.DiagnosticResult) interface{} {
	switch el := element.(type) {
	case *core.NestedDiagnosticResult:
		values := make(map[string]interface{}, len(el.Value))
		for _, value := range el.Value {
			values[value.Name()] = toJSONValue(value)
		}
		return values
	case *core.GenericDiagnosticResult:
		return el.Value
	case json.Marshaler:
		return el
	default:
		return element.String()
	}
}

func getRenderer(requestedContentType string) diagnosticsRenderer {
	switch requestedContentType {
	case "application/json":
		return renderAsJSON
	case "text/plain":
		fallthrough
	default:
		return renderAsText
	}
}
