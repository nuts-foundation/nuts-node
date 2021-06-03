/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
 */

package test

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

// AssertIsError asserts that expected is, or is the cause of the given actual error (according to errors.Is()).
func AssertIsError(t *testing.T, actual error, expected error) bool {
	if !errors.Is(actual, expected) {
		assert.Failf(t, "incorrect error", "actual error does not equal or is the wrapped in the given error\n\texpected: %v\n\tactual:%v", expected, actual)
		return false
	}
	return true
}