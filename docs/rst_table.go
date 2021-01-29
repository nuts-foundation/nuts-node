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
