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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
	"io"
	"os"
	"strings"
)

var _ PDPBackend = (*LocalPDP)(nil)

// New creates a new local policy backend
func New() *LocalPDP {
	return &LocalPDP{}
}

// LocalPDP is a backend for presentation definitions
// It loads a file with the mapping from oauth scope to PEX Policy.
// It allows access when the requester can present a submission according to the Presentation Definition.
type LocalPDP struct {
	backend PDPBackend
	config  Config
	// mapping holds the oauth scope to PEX Policy mapping
	mapping map[string]validatingWalletOwnerMapping
}

func (b *LocalPDP) Name() string {
	return ModuleName
}

func (b *LocalPDP) Configure(_ core.ServerConfig) error {
	// check if directory exists
	if b.config.Directory != "" {
		_, err := os.Stat(b.config.Directory)
		if err != nil {
			if os.IsNotExist(err) && b.config.Directory == defaultConfig().Directory {
				// assume this is the default config value and remove it
				b.config.Directory = ""
			} else {
				return fmt.Errorf("failed to load policy from directory: %w", err)
			}
		}
	}
	if b.config.Directory != "" {
		if err := b.loadFromDirectory(b.config.Directory); err != nil {
			return fmt.Errorf("failed to load policy from directory: %w", err)
		}
	}

	return nil
}

func (b *LocalPDP) Config() interface{} {
	return &b.config
}

func (b *LocalPDP) PresentationDefinitions(_ context.Context, scope string) (pe.WalletOwnerMapping, error) {
	result := pe.WalletOwnerMapping{}
	mapping, exists := b.mapping[scope]
	if !exists {
		return nil, ErrNotFound
	}
	for walletOwnerType, policy := range mapping {
		result[walletOwnerType] = policy
	}
	return result, nil
}

// loadFromDirectory traverses all .json files in the given directory and loads them
func (b *LocalPDP) loadFromDirectory(directory string) error {
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
		err := b.loadFromFile(fmt.Sprintf("%s/%s", directory, file.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadFromFile loads the mapping from the given file
func (b *LocalPDP) loadFromFile(filename string) error {
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
	result := make(map[string]validatingWalletOwnerMapping)
	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal PEX Policy mapping file %s: %w", filename, err)
	}
	if b.mapping == nil {
		b.mapping = make(map[string]validatingWalletOwnerMapping)
	}
	for scope, defs := range result {
		if _, exists := b.mapping[scope]; exists {
			return fmt.Errorf("mapping for scope '%s' already exists (file=%s)", scope, filename)
		}
		b.mapping[scope] = defs
	}
	return nil
}

// validatingPresentationDefinition is an alias for PresentationDefinition that validates the JSON on unmarshal.
type validatingWalletOwnerMapping pe.WalletOwnerMapping

func (v *validatingWalletOwnerMapping) UnmarshalJSON(data []byte) error {
	if err := v2.Validate(data, v2.WalletOwnerMapping); err != nil {
		return err
	}
	return json.Unmarshal(data, (*pe.WalletOwnerMapping)(v))
}
