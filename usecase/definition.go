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
	"bytes"
	"embed"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
	"github.com/santhosh-tekuri/jsonschema"
)

//go:embed *.json
var jsonSchemaFiles embed.FS
var definitionJsonSchema *jsonschema.Schema

func init() {
	usecaseDefinitionSchemaData, err := jsonSchemaFiles.ReadFile("usecase-definition-schema.json")
	if err != nil {
		panic(err)
	}
	const schemaURL = "http://nuts.nl/schemas/usecase-v0.json"
	if err := v2.Compiler.AddResource(schemaURL, bytes.NewReader(usecaseDefinitionSchemaData)); err != nil {
		panic(err)
	}
	definitionJsonSchema = v2.Compiler.MustCompile(schemaURL)
}

type Definition struct {
	ID                      string                    `json:"id"`
	Endpoint                string                    `json:"endpoint"`
	PresentationDefinition  pe.PresentationDefinition `json:"presentation_definition"`
	PresentationMaxValidity int                       `json:"presentation_max_validity"`
}

func parseDefinition(data []byte) (*Definition, error) {
	if err := definitionJsonSchema.Validate(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	var definition Definition
	if err := json.Unmarshal(data, &definition); err != nil {
		return nil, err
	}
	return &definition, nil
}
