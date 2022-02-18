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
	"github.com/nuts-foundation/go-did/vc"
)

// Reader contains all read-only operations for the concept registry
type Reader interface {
	// Concepts returns a list of concept configs
	Concepts() []Config
	// FindByType returns the Config if the given credentialType is registered, nil otherwise
	FindByType(credentialType string) *Config
	// QueryFor creates a query for the given concept.
	// The query is preloaded with required fixed values like the type.
	// It returns ErrUnknownConcept if the concept is not found
	QueryFor(concept string) (Query, error)
	// Transform a VerifiableCredential to concept format.
	Transform(concept string, VC vc.VerifiableCredential) (Concept, error)
}

// Writer contains state changing operations for the concept registry
type Writer interface {
	// Add a credential config to the registry
	Add(config Config) error
}

// Registry defines the interface for accessing loaded concepts and using the templates
// to generate queries and transform results.
type Registry interface {
	Reader
	Writer
}

const (
	// AuthorizationConcept is a concept required for authorization credentials
	AuthorizationConcept = "authorization"
	// OrganizationConcept is a concept required for the auth module to work
	OrganizationConcept = "organization"
	// OrganizationName defines the concept path for an organization name
	OrganizationName = "organization.name"
	// OrganizationCity defines the concept path for an organization city
	OrganizationCity = "organization.city"
)

// registry holds parsed credential configs which contain all the mappings from concept names to json paths.
// Queries are created through the conceptRegistry to add the correct templates.
// The registry can also do transformations of VCs to the correct format.
type registry struct {
	configs []Config
}

// NewRegistry creates a new registry instance with no templates.
func NewRegistry() Registry {
	r := &registry{
		configs: make([]Config, 0),
	}

	return r
}

func (r *registry) Concepts() []Config {
	return r.configs
}

// Add adds a new template to a concept and parses it.
func (r *registry) Add(config Config) error {
	// check for type
	if config.CredentialType == "" {
		return ErrNoType
	}

	r.configs = append(r.configs, config)

	return nil
}

// Transform a raw VC to a Concept
func (r *registry) Transform(concept string, VC vc.VerifiableCredential) (Concept, error) {
	if !r.hasConcept(concept) {
		return nil, ErrUnknownConcept
	}

	// find the correct template
	for _, u := range VC.Type {
		s := u.String()
		for _, c := range r.configs {
			if c.CredentialType == s && c.Concept == concept {
				return c.transform(VC)
			}
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

	for _, c := range r.configs {
		if c.Concept == concept {
			q.addConfig(c)
		}
	}

	return &q, nil
}

func (r *registry) FindByType(credentialType string) *Config {
	for _, c := range r.configs {
		if c.CredentialType == credentialType {
			return &c
		}
	}
	return nil
}

func (r *registry) hasConcept(concept string) bool {
	for _, c := range r.configs {
		if c.Concept == concept {
			return true
		}
	}
	return false
}
