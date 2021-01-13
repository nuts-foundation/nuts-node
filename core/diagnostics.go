/*
 * Nuts go core
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

// DiagnosticResult are the result of different checks giving information on how well the system is doing
type DiagnosticResult interface {
	// Name returns a simple and understandable name of the check
	Name() string

	// String returns the outcome of the check
	String() string
}

// GenericDiagnosticResult is a simple implementation of the DiagnosticResult interface
type GenericDiagnosticResult struct {
	Title   string
	Outcome string
}

// Name returns the name of the GenericDiagnosticResult
func (gdr *GenericDiagnosticResult) Name() string {
	return gdr.Title
}

// String returns the outcome of the GenericDiagnosticResult
func (gdr *GenericDiagnosticResult) String() string {
	return gdr.Outcome
}
