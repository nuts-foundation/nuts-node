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

// DiagnosticResult are the result of different checks giving information on how well the system is doing
type DiagnosticResult interface {
	// Name returns a simple and understandable name of the check
	Name() string

	// String returns the outcome of the check formatted as string
	String() string
}

// StringDiagnosticResult is an implementation of the DiagnosticResult interface that contains a single string as value.
type StringDiagnosticResult struct {
	Title string
	Value string
}

// Name returns the name of the StringDiagnosticResult
func (r *StringDiagnosticResult) Name() string {
	return r.Title
}

// String returns the outcome of the StringDiagnosticResult as string
func (r *StringDiagnosticResult) String() string {
	return r.Value
}

// NestedDiagnosticResult is an implementation of the DiagnosticResult interface that contains a slice of DiagnosticResult's.
type NestedDiagnosticResult struct {
	Title string
	Value []DiagnosticResult
}

// Name returns the name of the NestedDiagnosticResult
func (r *NestedDiagnosticResult) Name() string {
	return r.Title
}

// String returns the outcome of the NestedDiagnosticResult
func (r *NestedDiagnosticResult) Outcome() string {
	return fmt.Sprintf("%v", r.Value)
}