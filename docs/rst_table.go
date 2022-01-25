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

func printRstTable(header []rstValue, values [][]rstValue, writer io.StringWriter) {
	columnLengths := make([]int, len(header))
	rows := make([][]rstValue, len(values)+1)
	rows[0] = header
	for i, row := range values {
		rows[i+1] = row
	}
	for _, row := range rows {
		for i := 0; i < len(row); i++ {
			columnLengths[i] = intMax(columnLengths[i], len(row[i].value))
		}
	}
	dividers := []rstValue{
		{value: strings.Repeat("=", columnLengths[0])},
		{value: strings.Repeat("=", columnLengths[1])},
		{value: strings.Repeat("=", columnLengths[2])},
	}
	printRow(dividers, columnLengths, writer)
	printRow(rows[0], columnLengths, writer)
	printRow(dividers, columnLengths, writer)
	for i, row := range rows {
		if i == 0 {
			// Skip headers
			continue
		}
		printRow(row, columnLengths, writer)
	}
	printRow(dividers, columnLengths, writer)
}

func printRow(values []rstValue, columnLengths []int, writer io.StringWriter) {
	first := true
	for i := 0; i < len(columnLengths); i++ {
		if !first {
			writer.WriteString("  ")
		}
		cell := rstValue{}
		// Account for a row with less values than columns in the table
		if i < len(values) {
			cell = values[i]
		}
		writer.WriteString(cell.render() + strings.Repeat(" ", columnLengths[i]-len(cell.value)))
		first = false
	}
	writer.WriteString("\n")
}

func intMax(a int, b int) int {
	if a > b {
		return a
	}
	return b
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
