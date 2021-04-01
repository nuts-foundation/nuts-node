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
	"fmt"
	"runtime"
	"strings"
)

// GitCommit holds the latest git commit hash for this build.
var GitCommit string

// GitVersion holds the tagged version belonging to the git commit.
var GitVersion string

// GitBranch holds the branch from where the binary is built.
var GitBranch string = "development"

// Version gives the current version according to the git tag or the branch if there's no tag.
func Version() string {
	if GitVersion != "" && GitVersion != "undefined" {
		return GitVersion
	}
	return GitBranch
}

// OSArch returns the OS and Arch
func OSArch() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

func BuildInfo() string {
	b := strings.Builder{}
	b.WriteString("Git version: ")
	b.WriteString(Version())
	b.WriteString("\n")

	b.WriteString("Git commit: ")
	b.WriteString(GitCommit)
	b.WriteString("\n")

	b.WriteString("OS/Arch: ")
	b.WriteString(OSArch())
	b.WriteString("\n")

	return b.String()
}
