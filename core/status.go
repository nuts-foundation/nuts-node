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
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const moduleName = "Status"

type status struct {
	system *System
}

//NewStatusEngine creates a new Engine for viewing all engines
func NewStatusEngine(system *System) Engine {
	return &status{
		system: system,
	}
}

func (s *status) Name() string {
	return moduleName
}

func (s *status) Routes(router EchoRouter) {
	router.GET("/status/diagnostics", s.diagnosticsOverview)
	router.GET("/status", statusOK)
}

func (s *status) diagnosticsOverview(ctx echo.Context) error {
	return ctx.String(http.StatusOK, s.diagnosticsSummaryAsText())
}

func (s *status) diagnosticsSummaryAsText() string {
	var lines []string
	s.system.VisitEngines(func(engine Engine) {
		if m, ok := engine.(ViewableDiagnostics); ok {
			lines = append(lines, m.Name())
			diagnostics := m.Diagnostics()
			for _, d := range diagnostics {
				lines = append(lines, fmt.Sprintf("\t%s: %s", d.Name(), d.String()))
			}
		}
	})
	return strings.Join(lines, "\n")
}

// Diagnostics returns list of DiagnosticResult for the StatusEngine.
// The results are a list of all registered engines
func (s *status) Diagnostics() []DiagnosticResult {
	return []DiagnosticResult{&GenericDiagnosticResult{Title: "Registered engines", Outcome: strings.Join(s.listAllEngines(), ",")}}
}

func (s *status) listAllEngines() []string {
	var names []string
	s.system.VisitEngines(func(engine Engine) {
		if m, ok := engine.(Named); ok {
			names = append(names, m.Name())
		}
	})
	return names
}

// statusOK returns 200 OK with a "OK" body
func statusOK(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}
