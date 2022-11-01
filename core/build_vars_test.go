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

func TestBuildInfo(t *testing.T) {
	bi := BuildInfo()

	assert.Contains(t, bi, "Git version: 0")
	assert.Contains(t, bi, "Git commit: 0")
	assert.Contains(t, bi, "OS/Arch:")
}

func TestVersion(t *testing.T) {
	t.Run("no version, long commit ID", func(t *testing.T) {
		GitCommit = "abcdefghjiklmn"
		assert.Equal(t, "abcdefg", Version())
	})
	t.Run("no version, short commit ID", func(t *testing.T) {
		GitCommit = "abc"
		assert.Equal(t, "abc", Version())
	})
}
