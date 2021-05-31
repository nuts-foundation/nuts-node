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

// GenericDiagnosticResult is an implementation of the DiagnosticResult interface that contains a generic value.
type GenericDiagnosticResult struct {
	Title string
	Value interface{}
}

// Name returns the name of the GenericDiagnosticResult
func (r *GenericDiagnosticResult) Name() string {
	return r.Title
}

// String returns the outcome of the GenericDiagnosticResult as string
func (r *GenericDiagnosticResult) String() string {
	return fmt.Sprintf("%v", r.Value)
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
func (r *NestedDiagnosticResult) String() string {
	return fmt.Sprintf("%v", r.Value)
}
