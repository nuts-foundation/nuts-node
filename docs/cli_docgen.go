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
	"io"

	"github.com/spf13/cobra"
)

func GenerateCommandDocs(cmd *cobra.Command, writer io.Writer, filter func(command *cobra.Command) bool, printOptions bool) error {

	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultHelpFlag()

	if cmd.Runnable() {
		if filter(cmd) {
			// Command name
			name := cmd.CommandPath()
			_, _ = io.WriteString(writer, newline)
			writeHeader(writer, name, 2)

			// Description
			if len(cmd.Long) > 0 {
				_, _ = io.WriteString(writer, cmd.Long)
			} else {
				_, _ = io.WriteString(writer, cmd.Short)
			}
			_, _ = io.WriteString(writer, newline)

			// Usage
			_, _ = io.WriteString(writer, "\n::\n\n")
			_, _ = io.WriteString(writer, "  "+cmd.UseLine())
			_, _ = io.WriteString(writer, newline)
			_, _ = io.WriteString(writer, newline)
			if printOptions {
				writeCommandOptions(writer, cmd)
			}

			// Example
			if len(cmd.Example) > 0 {
				_, _ = io.WriteString(writer, "\n**Example**\n")
				_, _ = io.WriteString(writer, "\n::\n\n")
				_, _ = io.WriteString(writer, "  "+cmd.Example)
				_, _ = io.WriteString(writer, newline)
				_, _ = io.WriteString(writer, newline)
			}
		}
	} else {
		println("Not generating documentation for non-runnable command:", cmd.CommandPath())
	}

	// Generate docs for subcommands
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := GenerateCommandDocs(c, writer, filter, printOptions); err != nil {
			return err
		}
	}

	return nil
}

func writeCommandOptions(writer io.Writer, cmd *cobra.Command) {
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
}
