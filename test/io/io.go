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
	"fmt"
	"os"
	"regexp"
	"testing"
)

var invalidPathCharRegex = regexp.MustCompile("([^a-zA-Z0-9])")

// TestDirectory returns a temporary directory for this test only. Calling TestDirectory multiple times for the same
// instance of t returns a new directory every time.
func TestDirectory(t *testing.T) string {
	if dir, err := os.MkdirTemp("", normalizeTestName(t)); err != nil {
		t.Fatal(err)
		return ""
	} else {
		t.Cleanup(func() {
			if err := os.RemoveAll(dir); err != nil {
				_, _ = os.Stderr.WriteString(fmt.Sprintf("Unable to remove temporary directory for test (%s): %v\n", dir, err))
			}
		})

		return dir
	}
}

// TestWorkingDirectory is like TestDirectory but also changes the working directory to the test directory.
func TestWorkingDirectory(t *testing.T) string {
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
		return ""
	}
	if dir, err := os.MkdirTemp("", normalizeTestName(t)); err != nil {
		t.Fatal(err)
		return ""
	} else {
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
			return ""
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(dir); err != nil {
				_, _ = os.Stderr.WriteString(fmt.Sprintf("Unable to remove temporary directory for test (%s): %v\n", dir, err))
			}
			if err := os.Chdir(oldWd); err != nil {
				panic(err)
			}
		})

		return dir
	}
}

func normalizeTestName(t *testing.T) string {
	return invalidPathCharRegex.ReplaceAllString(t.Name(), "_")
}
