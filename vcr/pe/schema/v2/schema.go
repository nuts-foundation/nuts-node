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

// This package implements v2.0.0 of the Presentation Exchange specification
package v2

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema"
	"github.com/santhosh-tekuri/jsonschema/loader"
	"io"
)

//go:embed json-schema-draft-07.json
var jsonSchemaDraft07SchemaData []byte

const presentationDefinitionSchemaURL = "http://identity.foundation/presentation-exchange/schemas/presentation-definition.json"

//go:embed presentation_definition.json
var presentationDefinitionSchemaData []byte

//go:embed presentation-definition-claim-format-designations.json
var presentationDefinitionClaimFormatDesignationsSchemaData []byte

//go:embed presentation-submission-claim-format-designations.json
var presentationSubmissionClaimFormatDesignationsSchemaData []byte

const presentationSubmissionSchemaURL = "https://identity.foundation/presentation-exchange/schemas/presentation-submission.json"

//go:embed presentation_submission.json
var presentationSubmissionSchemaData []byte

// PresentationDefinition is the JSON schema for a presentation definition.
var PresentationDefinition *jsonschema.Schema

// PresentationSubmission is the JSON schema for a presentation submission.
var PresentationSubmission *jsonschema.Schema

func init() {
	// By default, it loads from filesystem, but that sounds unsafe.
	// Since register our schemas, we don't need to allow loading resources.
	loader.Load = func(url string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("refusing to load unknown schema: %s", url)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7
	resources := map[string][]byte{
		"http://json-schema.org/draft-07/schema": jsonSchemaDraft07SchemaData,
		"http://identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json": presentationDefinitionClaimFormatDesignationsSchemaData,
		presentationDefinitionSchemaURL: presentationDefinitionSchemaData,
		"http://identity.foundation/claim-format-registry/schemas/presentation-submission-claim-format-designations.json": presentationSubmissionClaimFormatDesignationsSchemaData,
		presentationSubmissionSchemaURL: presentationSubmissionSchemaData,
	}
	for u, data := range resources {
		if err := compiler.AddResource(u, bytes.NewReader(data)); err != nil {
			panic(fmt.Errorf("error compiling schema %s: %w", u, err))
		}
	}
	PresentationDefinition = compiler.MustCompile(presentationDefinitionSchemaURL)
	PresentationSubmission = compiler.MustCompile(presentationSubmissionSchemaURL)
}

// Validate validates the given data against the given schema.
func Validate(data []byte, schema *jsonschema.Schema) error {
	return schema.Validate(bytes.NewReader(data))
}
