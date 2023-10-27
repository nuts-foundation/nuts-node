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

package usecase

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"os"
	"path"
	"strings"
)

const ModuleName = "Usecase"

var _ core.Injectable = &Module{}
var _ core.Runnable = &Module{}
var _ core.Configurable = &Module{}
var _ ListWriter = &Module{}
var ErrMaintainerModeDisabled = errors.New("server is not a use case list maintainer")

func New() *Module {
	return &Module{}
}

type Module struct {
	config      Config
	maintainer  *maintainer
	definitions map[string]Definition
}

func (m *Module) Configure(_ core.ServerConfig) error {
	if m.config.Definitions.Directory == "" {
		return nil
	}
	var err error
	m.definitions, err = loadDefinitions(m.config.Definitions.Directory)
	if err != nil {
		return err
	}
	return nil
}

func (m *Module) Start() error {
	if len(m.config.Maintainer.DefinitionIDs) > 0 {
		// Get the definitions that are enabled for this maintainer
		var maintainedDefinitions []Definition
		for _, definitionID := range m.config.Maintainer.DefinitionIDs {
			if definition, exists := m.definitions[definitionID]; !exists {
				return fmt.Errorf("definition '%s' not found", definitionID)
			} else {
				maintainedDefinitions = append(maintainedDefinitions, definition)
			}
		}
		var err error
		m.maintainer, err = newMaintainer(m.config.Maintainer.Directory, maintainedDefinitions)
		if err != nil {
			return fmt.Errorf("unable to start maintainer: %w", err)
		}
	}
	return nil
}

func (m *Module) Shutdown() error {
	return nil
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) Config() interface{} {
	return &m.config
}

func (m *Module) Add(listName string, presentation vc.VerifiablePresentation) error {
	if m.maintainer == nil {
		return ErrMaintainerModeDisabled
	}
	return m.maintainer.Add(listName, presentation)
}

func (m *Module) Get(listName string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error) {
	if m.maintainer == nil {
		return nil, nil, ErrMaintainerModeDisabled
	}
	return m.maintainer.Get(listName, startAt)
}

func loadDefinitions(directory string) (map[string]Definition, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("unable to read definitions directory '%s': %w", directory, err)
	}
	result := make(map[string]Definition)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := path.Join(directory, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("unable to read definition file '%s': %w", filePath, err)
		}
		definition, err := parseDefinition(data)
		if err != nil {
			return nil, fmt.Errorf("unable to parse definition file '%s': %w", filePath, err)
		}
		if _, exists := result[definition.ID]; exists {
			return nil, fmt.Errorf("duplicate definition ID '%s' in file '%s'", definition.ID, filePath)
		}
		result[definition.ID] = *definition
	}
	return result, nil
}
