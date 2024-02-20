/*
 * Copyright (C) 2022 Nuts community
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

package jsonld

import (
	"bytes"
	"fmt"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld/log"
	"github.com/piprate/json-gold/ld"
)

var _ core.Configurable = (*jsonld)(nil)

type jsonld struct {
	config         Config
	documentLoader ld.DocumentLoader
}

// NewJSONLDInstance creates a new instance of the jsonld struct which implements the JSONLD interface
func NewJSONLDInstance() JSONLD {
	return &jsonld{
		config: DefaultConfig(),
	}
}

func (j *jsonld) DocumentLoader() ld.DocumentLoader {
	return j.documentLoader
}

func (j *jsonld) Configure(serverConfig core.ServerConfig) error {
	log.Logger().Tracef("Config: %v", j.config)
	loader, err := NewContextLoader(!serverConfig.Strictmode, j.config.Contexts)
	if err != nil {
		return err
	}
	j.documentLoader = loader
	return nil
}

func (j jsonld) Name() string {
	return moduleName
}

func (j *jsonld) Config() interface{} {
	return &j.config
}

// AllFieldsDefined tests whether all fields are defined in the JSON-LD context(s) of the input.
func AllFieldsDefined(DocumentLoader ld.DocumentLoader, inputJSON []byte) error {
	document, err := ld.DocumentFromReader(bytes.NewReader(inputJSON))
	if err != nil {
		return err
	}

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = DocumentLoader
	options.SafeMode = true

	// expand with safe mode enabled, which asserts that all properties are defined in the JSON-LD context.
	if _, err = processor.Expand(document, options); err != nil {
		return fmt.Errorf("jsonld: %w", err)
	}
	return nil
}
