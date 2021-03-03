/*
 * Copyright (C) 2021. Nuts community
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

package dag

import (
	"fmt"
	"strings"
)

// DotGraphVisitor is a graph visitor that outputs the walked path as "dot" diagram.
// The is currently unused, but can be used to debug the DAG to see how transactions relate to each other. The output
// can be viewed using a DOT plugin or when rendering the DOT file to SVG/PNG, etc.
type DotGraphVisitor struct {
	output      string
	aliases     map[string]string
	counter     int
	labelStyle  LabelStyle
	showAliases bool
	showContent bool

	nodes []string
	edges []string
}

// LabelStyle defines node label styles for DotGraphVisitor.
type LabelStyle int

const (
	// ShowAliasLabelStyle is a style that uses integer aliases for node labels.
	ShowAliasLabelStyle LabelStyle = iota
	// ShowAliasLabelStyle is a style that uses the references of nodes as label.
	ShowRefLabelStyle LabelStyle = iota
)

func NewDotGraphVisitor(labelStyle LabelStyle) *DotGraphVisitor {
	return &DotGraphVisitor{
		aliases:    map[string]string{},
		labelStyle: labelStyle,
	}
}

func (d *DotGraphVisitor) Accept(transaction Transaction) {
	d.counter++
	d.nodes = append(d.nodes, fmt.Sprintf("  \"%s\"[label=\"%s (%d)\"]", transaction.Ref().String(), d.label(transaction), d.counter))
	for _, prev := range transaction.Previous() {
		d.edges = append(d.edges, fmt.Sprintf("  \"%s\" -> \"%s\"", prev.String(), transaction.Ref().String()))
	}
}

func (d *DotGraphVisitor) Render() string {
	var lines []string
	lines = append(lines, "digraph {")
	lines = append(lines, d.nodes...)
	lines = append(lines, d.edges...)
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

func (d *DotGraphVisitor) label(transaction Transaction) string {
	switch d.labelStyle {
	case ShowAliasLabelStyle:
		if alias, ok := d.aliases[transaction.Ref().String()]; ok {
			return alias
		} else {
			alias = fmt.Sprintf("%d", len(d.aliases)+1)
			d.aliases[transaction.Ref().String()] = alias
			return alias
		}
	case ShowRefLabelStyle:
		fallthrough
	default:
		return transaction.Ref().String()
	}
}
