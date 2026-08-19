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

package main

import (
	"fmt"
	"io"
	"strings"
)

// printRstTable renders the rows as the content of a list-table directive.
// Each row is a self-contained block, so adding or changing a row never reformats
// the other rows (unlike a simple table, where every cell is padded to the widest
// value in its column and a single long value rewrites the entire table).
func printRstTable(header []rstValue, values [][]rstValue, writer io.StringWriter) {
	printRow(header, len(header), writer)
	for _, row := range values {
		printRow(row, len(header), writer)
	}
}

func printRow(values []rstValue, columns int, writer io.StringWriter) {
	for i := 0; i < columns; i++ {
		prefix := "    * - "
		if i > 0 {
			prefix = "      - "
		}
		cell := rstValue{}
		// Account for a row with less values than columns in the table
		if i < len(values) {
			cell = values[i]
		}
		rendered := cell.render()
		if rendered == "" {
			// Avoid trailing whitespace on empty cells
			prefix = strings.TrimRight(prefix, " ")
		}
		writer.WriteString(prefix + rendered + "\n")
	}
}

type rstValue struct {
	value string
	bold  bool
}

func (v rstValue) render() string {
	rendered := v.value
	// Escape
	if strings.HasPrefix(rendered, ":") {
		rendered = fmt.Sprintf("\\%s", rendered)
	}
	//
	if v.bold {
		rendered = fmt.Sprintf("**%s**", rendered)
	}
	return rendered
}

func val(value string) rstValue {
	return rstValue{value: value}
}

func vals(value ...string) []rstValue {
	result := make([]rstValue, len(value))
	for i, v := range value {
		result[i] = val(v)
	}
	return result
}
