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

package concept

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistry_Add(t *testing.T) {
	t.Run("when template is added", func(t *testing.T) {
		r := NewRegistry().(*registry)

		err := r.Add(ExampleConfig)
		if !assert.NoError(t, err) {
			return
		}

		t.Run("template is added", func(t *testing.T) {
			assert.Len(t, r.configs, 1)
		})
	})
}
