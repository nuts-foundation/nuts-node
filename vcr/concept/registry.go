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

// Registry defines the interface for accessing loaded credential config
type Registry interface {
	// Add a credential config to the registry
	Add(config Config) error
}

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
	r.configs = append(r.configs, config)

	return nil
}
