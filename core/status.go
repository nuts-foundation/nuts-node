/*
 * Nuts go
 * Copyright (C) 2019 Nuts community
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
	"github.com/spf13/cobra"
)

//NewStatusEngine creates a new Engine for viewing all engines
func NewStatusEngine() *Engine {
	return &Engine{
		Name: "Status",
		Cmd: &cobra.Command{
			Use:   "diagnostics",
			Short: "show engine diagnostics",
			Run: func(cmd *cobra.Command, args []string) {
				diagnosticsSummaryAsText()
			},
		},
		Diagnostics: func() []DiagnosticResult {
			return []DiagnosticResult{diagnostics()}
		},
		Routes: func(router EchoRouter) {
			router.GET("/status/diagnostics", diagnosticsOverview)
			router.GET("/status", StatusOK)
		},
	}
}

func diagnosticsOverview(ctx echo.Context) error {
	return ctx.String(http.StatusOK, diagnosticsSummaryAsText())
}

func diagnosticsSummaryAsText() string {
	var lines []string
	for _, e := range EngineCtl.Engines {
		if e.Diagnostics != nil {
			lines = append(lines, e.Name)
			diagnostics := e.Diagnostics()
			for _, d := range diagnostics {
				lines = append(lines, fmt.Sprintf("\t%s: %s", d.Name(), d.String()))
			}
		}
	}

	return strings.Join(lines, "\n")
}

func diagnostics() DiagnosticResult {
	return &GenericDiagnosticResult{Title: "Registered engines", Outcome: strings.Join(listAllEngines(), ",")}
}

// StatusOK returns 200 OK with a "OK" body
func StatusOK(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}

func listAllEngines() []string {
	var names []string
	for _, e := range EngineCtl.Engines {
		names = append(names, e.Name)
	}
	return names
}
