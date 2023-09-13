/*
 * Copyright (C) 2023 Nuts community
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

package pe

import (
	"encoding/json"
	"io"
	"os"
)

// DefinitionResolver is a store for presentation definitions
// It loads a file with the mapping from oauth scope to presentation definition
type DefinitionResolver struct {
	// mapping holds the oauth scope to presentation definition mapping
	mapping map[string]PresentationDefinition
}

// LoadFromFile loads the mapping from the given file
func (s *DefinitionResolver) LoadFromFile(filename string) error {
	// read the bytes from the file
	reader, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// unmarshal the bytes into the mapping
	s.mapping = make(map[string]PresentationDefinition)
	return json.Unmarshal(bytes, &s.mapping)
}

// ByScope returns the presentation definition for the given scope.
// Returns nil if it doesn't exist or if no mappings are loaded.
func (s *DefinitionResolver) ByScope(scope string) *PresentationDefinition {
	mapping, ok := s.mapping[scope]
	if !ok {
		return nil
	}
	return &mapping
}
