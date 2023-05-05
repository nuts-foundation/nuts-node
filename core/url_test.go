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

package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJoinURLPaths(t *testing.T) {
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "/path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com/", "/path"))
	assert.Equal(t, "http://example.com/path/", JoinURLPaths("http://example.com/", "/path/"))
	assert.Equal(t, "http://example.com", JoinURLPaths("http://example.com"))
	assert.Equal(t, "", JoinURLPaths())
}
