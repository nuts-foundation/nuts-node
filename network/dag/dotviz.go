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
	aliases    map[string]string
	counter    int
	labelStyle LabelStyle

	nodes []string
	edges []string
}

// LabelStyle defines node label styles for DotGraphVisitor.
type LabelStyle int

const (
	// ShowAliasLabelStyle is a style that uses integer aliases for node labels.
	ShowAliasLabelStyle LabelStyle = iota
	// ShowRefLabelStyle is a style that uses the references of nodes as label.
	ShowRefLabelStyle LabelStyle = iota
	// ShowShortRefLabelStyle is a style that uses a shorter version of the references of nodes as label.
	ShowShortRefLabelStyle LabelStyle = iota
)

// NewDotGraphVisitor creates a new DotGraphVisitor
func NewDotGraphVisitor(labelStyle LabelStyle) *DotGraphVisitor {
	return &DotGraphVisitor{
		aliases:    map[string]string{},
		labelStyle: labelStyle,
	}
}

// Accept adds a transaction to the dot graph. Should be called by the DAG walker.
func (d *DotGraphVisitor) Accept(transaction Transaction, _ PayloadReader) bool {
	d.counter++
	d.nodes = append(d.nodes, fmt.Sprintf("  \"%s\"[label=\"%s (%d)\"]", transaction.Ref().String(), d.label(transaction), d.counter))
	for _, prev := range transaction.Previous() {
		d.edges = append(d.edges, fmt.Sprintf("  \"%s\" -> \"%s\"", prev.String(), transaction.Ref().String()))
	}
	return true
}

// Render returns the walked DAG visualized as dot graph.
func (d *DotGraphVisitor) Render() string {
	var lines []string
	lines = append(lines, "digraph {")
	lines = append(lines, d.nodes...)
	lines = append(lines, d.edges...)
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

func (d *DotGraphVisitor) label(transaction Transaction) string {
	ref := transaction.Ref().String()
	switch d.labelStyle {
	case ShowAliasLabelStyle:
		return d.getAlias(ref, func(ref string) string {
			return fmt.Sprintf("%d", len(d.aliases)+1)
		})
	case ShowShortRefLabelStyle:
		return d.getAlias(ref, func(ref string) string {
			return fmt.Sprintf("%s..%s", ref[:4], ref[len(ref)-4:])
		})
	case ShowRefLabelStyle:
		fallthrough
	default:
		return ref
	}
}

func (d *DotGraphVisitor) getAlias(ref string, aliaser func(ref string) string) string {
	alias, _ := d.aliases[ref]
	if alias == "" {
		alias = aliaser(ref)
		d.aliases[ref] = alias
	}
	return alias
}
