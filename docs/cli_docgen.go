/*
 * Copyright (C) 2022 Nuts community
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
	"github.com/spf13/cobra"
	"io"
	"strings"
)

func GenerateCommandDocs(cmd *cobra.Command, writer io.Writer) error {
	const newline = "\n"

	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultHelpFlag()

	if cmd.Runnable() {
		// Command name
		name := cmd.CommandPath()
		_, _ = io.WriteString(writer, newline)
		_, _ = io.WriteString(writer, name)
		_, _ = io.WriteString(writer, newline)
		_, _ = io.WriteString(writer, strings.Repeat("^", len(name)))
		_, _ = io.WriteString(writer, newline)
		_, _ = io.WriteString(writer, newline)

		// Description
		if len(cmd.Long) > 0 {
			_, _ = io.WriteString(writer, cmd.Long)
		} else {
			_, _ = io.WriteString(writer, cmd.Short)
		}
		_, _ = io.WriteString(writer, newline)

		// Options
		_, _ = io.WriteString(writer, "\n::\n\n")
		_, _ = io.WriteString(writer, "  "+cmd.UseLine())
		_, _ = io.WriteString(writer, newline)
		_, _ = io.WriteString(writer, newline)
		flags := cmd.NonInheritedFlags()
		if flags.HasAvailableFlags() {
			flags.SetOutput(writer)
			flags.PrintDefaults()
		}
		parentFlags := cmd.InheritedFlags()
		if parentFlags.HasAvailableFlags() {
			parentFlags.SetOutput(writer)
			parentFlags.PrintDefaults()
		}
	} else {
		println("Not generating documentation for non-runnable command:", cmd.CommandPath())
	}

	// Generate docs for subcommands
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := GenerateCommandDocs(c, writer); err != nil {
			return err
		}
	}

	return nil
}
