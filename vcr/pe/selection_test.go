/*
 * Copyright (C) 2026 Nuts community
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

package pe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScalarAsText(t *testing.T) {
	testCases := []struct {
		name       string
		value      any
		expected   string
		comparable bool
	}{
		{name: "string is used as is", value: "URA-001", expected: "URA-001", comparable: true},
		{name: "empty string is comparable", value: "", expected: "", comparable: true},
		{name: "whole number has no decimals", value: float64(3), expected: "3", comparable: true},
		{name: "fraction keeps its decimals", value: 1.5, expected: "1.5", comparable: true},
		{name: "large number has no exponent", value: float64(123456789012), expected: "123456789012", comparable: true},
		{name: "negative number", value: float64(-2), expected: "-2", comparable: true},
		{name: "true", value: true, expected: "true", comparable: true},
		{name: "false", value: false, expected: "false", comparable: true},
		{name: "array is not comparable", value: []any{"a"}},
		{name: "object is not comparable", value: map[string]any{"a": "b"}},
		{name: "nil is not comparable", value: nil},
		{name: "non-JSON number type is not comparable", value: 3},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := ScalarAsText(tc.value)

			assert.Equal(t, tc.comparable, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
