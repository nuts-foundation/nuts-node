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

import (
	"github.com/nuts-foundation/go-did"
)

// Registry defines the interface for accessing loaded concepts and using the templates
// to generate queries and transform results.
type Registry interface {
	// ConceptTemplates returns a mapping of concept names to parsed templates.
	ConceptTemplates() map[string][]*Template
	// Add a conceptTemplate to the registry
	Add(conceptTemplate *Template) error
	// QueryFor creates a query for the given concept.
	// The query is preloaded with required fixed values like the type.
	// It returns ErrUnknownConcept if the concept is not found
	QueryFor(concept string) (Query, error)
	// Transform a VerifiableCredential to concept format.
	Transform(concept string, VC did.VerifiableCredential) (Concept, error)
}

// registry holds parsed concepts which contain all the mappings from concept names to json paths.
// Queries are created through the conceptRegistry to add the correct templates.
// The registry can also do transformations of VCs and queries to the correct format.
// Concepts are automatically determined from the ConceptTemplates
// a concept value of <<organization.name>> creates the concept "organization"
type registry struct {
	conceptTemplates map[string][]*Template
	typedTemplates   map[string]*Template
}

// NewRegistry creates a new registry instance with no templates.
func NewRegistry() Registry {
	r := &registry{
		conceptTemplates: map[string][]*Template{},
		typedTemplates:   map[string]*Template{},
	}

	return r
}

func (r *registry) ConceptTemplates() map[string][]*Template {
	ct := make(map[string][]*Template, len(r.conceptTemplates))

	// without generics we need to convert the template pointers to Template interface
	for k, v := range r.conceptTemplates {
		ts := make([]*Template, len(v))
		for i, t := range v {
			ts[i] = t
		}
		ct[k] = ts
	}

	return ct
}

// AddFromString adds a new template to a concept and parses it.
func (r *registry) Add(conceptTemplate *Template) error {
	// add to list of templates for same concept name
	for _, c := range conceptTemplate.rootConcepts() {
		current, ok := r.conceptTemplates[c]
		if !ok {
			current = []*Template{}
		}
		current = append(current, conceptTemplate)
		r.conceptTemplates[c] = current
	}

	// add to map of specific VC type to template
	v, ok := conceptTemplate.fixedValues[TypeField]
	if !ok || v == "" {
		return ErrNoType
	}
	r.typedTemplates[v] = conceptTemplate

	return nil
}

// Transform a raw VC to a Concept
func (r *registry) Transform(concept string, VC did.VerifiableCredential) (Concept, error) {
	if !r.hasConcept(concept) {
		return nil, ErrUnknownConcept
	}

	// find the correct template
	for _, u := range VC.Type {
		s := u.String()
		if t, ok := r.typedTemplates[s]; ok {
			return t.transform(VC)
		}
	}

	return nil, ErrNoType
}

// QueryFor returns a query specific for the given concept.
// Returns ErrUnknownConcept for an unknown concept.
func (r *registry) QueryFor(concept string) (Query, error) {
	if !r.hasConcept(concept) {
		return nil, ErrUnknownConcept
	}

	q := query{
		concept: concept,
	}

	for _, t := range r.conceptTemplates[concept] {
		q.addTemplate(t)
	}

	return &q, nil
}

func (r *registry) hasConcept(concept string) bool {
	_, ok := r.conceptTemplates[concept]
	return ok
}
