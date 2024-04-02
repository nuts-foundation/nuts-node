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

// Package v2 implements v2.0.0 of the Presentation Exchange specification
package v2

import (
	"bytes"
	"embed"
	_ "embed"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema"
	"github.com/santhosh-tekuri/jsonschema/loader"
	"io"
	"io/fs"
	"strings"
)

const (
	inputDescriptor                               = "http://identity.foundation/presentation-exchange/schemas/input-descriptor.json"
	presentationDefinitionEnvelope                = "http://identity.foundation/presentation-exchange/schemas/presentation-definition-envelope.json"
	presentationDefinition                        = "http://identity.foundation/presentation-exchange/schemas/presentation-definition.json"
	presentationSubmission                        = "http://identity.foundation/presentation-exchange/schemas/presentation-submission.json"
	submissionRequirement                         = "http://identity.foundation/presentation-exchange/schemas/submission-requirement.json"
	submissionRequirements                        = "http://identity.foundation/presentation-exchange/schemas/submission-requirements.json"
	presentationSubmissionClaimFormatDesignations = "http://identity.foundation/claim-format-registry/schemas/presentation-submission-claim-format-designations.json"
	presentationDefinitionClaimFormatDesignations = "http://identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json"
	multiPEX                                      = "http://nuts.nl/schemas/walletownermapping.json"
)

//go:embed *.json
var schemaFiles embed.FS

// WalletOwnerMapping is the JSON schema for a WalletOwnerMapping (presentation definition with a specific audience).
var WalletOwnerMapping *jsonschema.Schema

// PresentationDefinition is the JSON schema for a presentation definition.
var PresentationDefinition *jsonschema.Schema

// PresentationSubmission is the JSON schema for a presentation submission.
var PresentationSubmission *jsonschema.Schema

// Compiler returns a JSON schema compiler with the Presentation Exchange schemas loaded.
func Compiler() *jsonschema.Compiler {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7
	if err := loadSchemas(schemaFiles, compiler); err != nil {
		panic(err)
	}
	return compiler
}

func init() {
	// By default, it loads from filesystem, but that sounds unsafe.
	// Since register our schemas, we don't need to allow loading resources.
	loader.Load = func(url string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("refusing to load unknown schema: %s", url)
	}
	compiler := Compiler()
	PresentationDefinition = compiler.MustCompile(presentationDefinition)
	PresentationSubmission = compiler.MustCompile(presentationSubmission)
	WalletOwnerMapping = compiler.MustCompile(multiPEX)
}

func loadSchemas(reader fs.ReadFileFS, compiler *jsonschema.Compiler) error {
	var resources = map[string]string{
		"http://json-schema.org/draft-07/schema": "json-schema-draft-07.json",
	}
	schemaURLs := []string{
		inputDescriptor,
		presentationDefinitionEnvelope,
		presentationDefinition,
		presentationSubmission,
		submissionRequirement,
		submissionRequirements,
		presentationSubmissionClaimFormatDesignations,
		presentationDefinitionClaimFormatDesignations,
		multiPEX,
	}
	for _, schemaURL := range schemaURLs {
		// Last part of schema URL matches the embedded file's name
		parts := strings.Split(schemaURL, "/")
		fileName := parts[len(parts)-1]
		resources[schemaURL] = fileName
	}
	for schemaURL, fileName := range resources {
		data, err := reader.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("error reading schema file %s: %w", fileName, err)
		}
		if err := compiler.AddResource(schemaURL, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("error compiling schema %s: %w", schemaURL, err)
		}
	}
	return nil
}

// Validate validates the given data against the given schema.
func Validate(data []byte, schema *jsonschema.Schema) error {
	return schema.Validate(bytes.NewReader(data))
}
