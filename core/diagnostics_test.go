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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiagnosticResultMap_Name(t *testing.T) {
	gdr := DiagnosticResultMap{Title: "test"}

	assert.Equal(t, "test", gdr.Name())
}

func TestDiagnosticResultMap_String(t *testing.T) {
	gdr := DiagnosticResultMap{Items: []DiagnosticResult{GenericDiagnosticResult{Title: "Foo"}}}

	assert.Equal(t, "map[Foo:<nil>]", gdr.String())
}

func TestDiagnosticResultMap_Result(t *testing.T) {
	gdr := DiagnosticResultMap{Items: []DiagnosticResult{
		GenericDiagnosticResult{Title: "Foo", Outcome: 1},
		GenericDiagnosticResult{Title: "Bar", Outcome: 2},
	}}

	assert.Equal(t, map[string]interface{}{"Foo": 1, "Bar": 2}, gdr.Result())

}

func TestGenericDiagnosticResult_Name(t *testing.T) {
	gdr := GenericDiagnosticResult{Title: "test"}

	assert.Equal(t, "test", gdr.Name())
}

func TestGenericDiagnosticResult_String(t *testing.T) {
	gdr := GenericDiagnosticResult{Outcome: "test"}

	assert.Equal(t, "test", gdr.String())
}

func TestGenericDiagnosticResult_Result(t *testing.T) {
	gdr := GenericDiagnosticResult{Outcome: 5}

	assert.Equal(t, 5, gdr.Result())
}
