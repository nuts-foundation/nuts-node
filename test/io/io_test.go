/*
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

package io

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_normalizeTestName(t *testing.T) {
	t.Run("level 1!@#!@3", func(t *testing.T) {
		t.Run("level 2!!", func(t *testing.T) {
			assert.Equal(t, "Test_normalizeTestName_level_1_____3_level_2__", normalizeTestName(t))
		})
	})
}
