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

import "fmt"

// MappedDiagnosable is implemented by types that want to
type MappedDiagnosable interface {
	MappedDiagnostics() map[string]func() Diagnosable
}

// DiagnosticResult are the result of different checks giving information on how well the system is doing
type DiagnosticResult interface {
	// Name returns a simple and understandable name of the check
	Name() string

	// Result returns the outcome of the check in its original format. This may be any type that can be marshalled by the JSON package.
	Result() interface{}

	// String returns the outcome of the check formatted as string
	String() string
}

// DiagnosticResultMap is a DiagnosticResult that presents the given Items as a map, rather than a list.
type DiagnosticResultMap struct {
	Title string
	Items []DiagnosticResult
}

// Name returns the of the diagnostic, which is used as key.
func (g DiagnosticResultMap) Name() string {
	return g.Title
}

// Result returns the result of the diagnostic, which is Items converted to a map.
func (g DiagnosticResultMap) Result() interface{} {
	result := make(map[string]interface{}, 0)
	for _, item := range g.Items {
		result[item.Name()] = item.Result()
	}
	return result
}

// String returns the string representation of Result()
func (g DiagnosticResultMap) String() string {
	return fmt.Sprintf("%v", g.Result())
}

// GenericDiagnosticResult is a simple implementation of the DiagnosticResult interface
type GenericDiagnosticResult struct {
	Title   string
	Outcome interface{}
}

// Result returns the raw outcome of the GenericDiagnosticResult
func (gdr GenericDiagnosticResult) Result() interface{} {
	return gdr.Outcome
}

// Name returns the name of the GenericDiagnosticResult
func (gdr GenericDiagnosticResult) Name() string {
	return gdr.Title
}

// String returns the outcome of the GenericDiagnosticResult
func (gdr GenericDiagnosticResult) String() string {
	return fmt.Sprintf("%v", gdr.Outcome)
}
