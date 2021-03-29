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

package concept

// Query is an DB query abstraction.
// it is created from the registry in the context of a concept.
// It contains concept specific query arguments, that need to be resolved by the DB facade using the template registry.
type Query interface {
	// Concept returns the concept name.
	Concept() string
	// Parts returns the different TemplateQuery
	Parts() []*TemplateQuery
	// AddClause adds a clause to the query.
	AddClause(clause Clause)
}

type query struct {
	concept string
	parts   []*TemplateQuery
}

func (q query) Concept() string {
	return q.concept
}

func (q query) Parts() []*TemplateQuery {
	return q.parts
}

// addTemplate adds a template to this query. It'll create a new TemplateQuery preconfigured with the template's hard coded values.
func (q *query) addTemplate(template *Template) {
	tq := TemplateQuery{
		template: template,
	}

	q.parts = append(q.parts, &tq)
}

// Add a Clause. The clause is added to each TemplateQuery
func (q *query) AddClause(clause Clause) {
	for _, tq := range q.parts {
		tq.Clauses = append(tq.Clauses, clause)
	}
}

// TemplateQuery represents a query/template combination
type TemplateQuery struct {
	template *Template
	Clauses  []Clause
}

// Template returns the underlying template
func (tq *TemplateQuery) Template() *Template {
	return tq.template
}

// VCType returns the VC type.
func (tq *TemplateQuery) VCType() string {
	return tq.template.VCType()
}

// Clause abstracts different equality clauses, comparable to '=', '!=', 'between' and 'abc%' in SQL.
// note: it currently only supports a key/value store with a binary tree index.
// When other DB's need to be supported, it could be the case that we will have to add 'dialects' for queries.
type Clause interface {
	// Key returns the key to match against.
	Key() string
	// Seek returns the first matching value for this Clause or "" if not applicable.
	Seek() string
	// Match returns the string that should match each subsequent test when using a cursor or something equal.
	Match() string
	// Type returns the clause identifier type. This type is used for mapping to the underlying DB query language
	Type() string
}

// EqType is the identifier for an equals clause
const EqType = "eq"

// Eq creates an equal Clause
func Eq(key string, value string) Clause {
	return eq{key, value}
}

type eq struct {
	key   string
	value string
}

func (e eq) Type() string {
	return EqType
}

func (e eq) Key() string {
	return e.key
}

func (e eq) Seek() string {
	return e.value
}

func (e eq) Match() string {
	return e.value
}

// EqType is the identifier for an equals clause
const PrefixType = "prefix"

// Prefix creates a prefix Clause
func Prefix(key string, value string) Clause {
	return prefix{key, value}
}

type prefix struct {
	key   string
	value string
}

func (e prefix) Type() string {
	return PrefixType
}

func (e prefix) Key() string {
	return e.key
}

func (e prefix) Seek() string {
	return e.value
}

func (e prefix) Match() string {
	return e.value
}
