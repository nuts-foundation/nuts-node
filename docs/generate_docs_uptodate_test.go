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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeneratedDocsAreUpToDate fails when the generated documentation differs from what is committed,
// so a contributor who changed a config option or CLI command but forgot to run `make cli-docs` is caught by CI.
func TestGeneratedDocsAreUpToDate(t *testing.T) {
	system := cmd.CreateSystem(func() {})
	for fileName, expected := range generatedDocFiles(system) {
		// generatedDocFiles keys are repo-relative paths (docs/...); tests run from the docs/ package directory.
		committed, err := os.ReadFile(filepath.Join("..", fileName))
		require.NoError(t, err)
		assert.Equalf(t, string(committed), string(expected),
			"%s is out of date; run `make cli-docs` and commit the result", fileName)
	}
}
