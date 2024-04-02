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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/policy/api/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
	"io"
	"os"
	"strings"
)

// localPDP is a backend for presentation definitions
// It loads a file with the mapping from oauth scope to presentation definition.
// It allows access when the requester can present a submission according to the Presentation Definition. It does not do any additional authorization checks.
type localPDP struct {
	// mapping holds the oauth scope to presentation definition mapping
	mapping map[string]validatingPresentationDefinition
}

func (b *localPDP) PresentationDefinition(_ context.Context, _ did.DID, scope string) (*pe.PresentationDefinition, error) {
	mapping, ok := b.mapping[scope]
	if !ok {
		return nil, ErrNotFound
	}
	result := pe.PresentationDefinition(mapping)
	return &result, nil
}

func (b *localPDP) Authorized(_ context.Context, _ client.AuthorizedRequest) (bool, error) {
	return true, nil
}

// loadFromDirectory traverses all .json files in the given directory and loads them
func (s *localPDP) loadFromDirectory(directory string) error {
	// open the directory
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()

	// read all the files in the directory
	files, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	// load all the files
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		err := s.loadFromFile(fmt.Sprintf("%s/%s", directory, file.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadFromFile loads the mapping from the given file
func (s *localPDP) loadFromFile(filename string) error {
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
	result := make(map[string]validatingPresentationDefinition)
	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Presentation Exchange mapping file %s: %w", filename, err)
	}
	if s.mapping == nil {
		s.mapping = make(map[string]validatingPresentationDefinition)
	}
	for scope, defs := range result {
		if _, exists := s.mapping[scope]; exists {
			return fmt.Errorf("mapping for scope '%s' already exists (file=%s)", scope, filename)
		}
		s.mapping[scope] = defs
	}
	return nil
}

// validatingPresentationDefinition is an alias for PresentationDefinition that validates the JSON on unmarshal.
type validatingPresentationDefinition pe.PresentationDefinition

func (v *validatingPresentationDefinition) UnmarshalJSON(data []byte) error {
	if err := v2.Validate(data, v2.PresentationDefinition); err != nil {
		return err
	}
	return json.Unmarshal(data, (*pe.PresentationDefinition)(v))
}
