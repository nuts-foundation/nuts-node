/*
 * Copyright (C) 2023 Nuts community
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

package http

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddQueryParams(t *testing.T) {
	t.Run("new key", func(t *testing.T) {
		u, _ := url.Parse("https://test.test?test=1")

		result := AddQueryParams(*u, map[string]string{"test2": "2"})

		assert.Equal(t, "https://test.test?test=1&test2=2", result.String())
	})

	t.Run("multiple params with same key", func(t *testing.T) {
		u, _ := url.Parse("https://test.test?test=1")

		result := AddQueryParams(*u, map[string]string{"test1": "2"})

		assert.Equal(t, "https://test.test?test=1&test1=2", result.String())
	})
}
