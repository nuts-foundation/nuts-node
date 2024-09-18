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

package discovery

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
var serviceDefinitionJsonSchema *jsonschema.Schema

func init() {
	serviceDefinitionSchemaData, err := jsonSchemaFiles.ReadFile("service-definition-schema.json")
	if err != nil {
		panic(err)
	}
	const schemaURL = "http://nuts.nl/schemas/discovery-service-v0.json"
	compiler := v2.Compiler()
	if err := compiler.AddResource(schemaURL, bytes.NewReader(serviceDefinitionSchemaData)); err != nil {
		panic(err)
	}
	serviceDefinitionJsonSchema = compiler.MustCompile(schemaURL)
}

// ServiceDefinition holds the definition of a service.
type ServiceDefinition struct {
	// ID is the unique identifier of the use case.
	ID string `json:"id"`
	// DIDMethods is a list of DID methods that are supported by the use case.
	// If empty, all methods are supported.
	DIDMethods []string `json:"did_methods"`
	// Endpoint is the endpoint where the use case list is served.
	Endpoint string `json:"endpoint"`
	// PresentationDefinition specifies the Presentation ServiceDefinition submissions to the list must conform to,
	// according to the Presentation Exchange specification.
	PresentationDefinition pe.PresentationDefinition `json:"presentation_definition"`
	// PresentationMaxValidity specifies how long submitted presentations are allowed to be valid (in seconds).
	PresentationMaxValidity int `json:"presentation_max_validity"`
}

// ParseServiceDefinition validates the input against the JSON schema for service definitions.
// If the input is valid, it is parsed and returned as a ServiceDefinition.
func ParseServiceDefinition(data []byte) (*ServiceDefinition, error) {
	if err := serviceDefinitionJsonSchema.Validate(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	var definition ServiceDefinition
	if err := json.Unmarshal(data, &definition); err != nil {
		return nil, err
	}
	return &definition, nil
}
