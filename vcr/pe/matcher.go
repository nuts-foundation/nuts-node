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
	"errors"
	"fmt"
	"github.com/PaesslerAG/jsonpath"
	"github.com/dlclark/regexp2"
	"github.com/nuts-foundation/go-did/vc"
)

// ErrUnsupportedFilter is returned when a filter uses unsupported features.
var ErrUnsupportedFilter = errors.New("unsupported filter")

// todo check VC format with requested format

func Match(presentationDefinition PresentationDefinition, vcs []vc.VerifiableCredential) (PresentationSubmission, []vc.VerifiableCredential, error) {
	// for each VC in vcs:
	// for each descriptor in presentation_definition.descriptors:
	// for each constraint in descriptor.constraints:
	// for each field in constraint.fields:
	//   a vc must match the field
	presentationSubmission := PresentationSubmission{
		Id:           presentationDefinition.Id, // todo random
		DefinitionId: presentationDefinition.Id,
	}
	var matchingCredentials []vc.VerifiableCredential
	for i, inputDescriptor := range presentationDefinition.InputDescriptors {
		var mapping *InputDescriptorMappingObject
		var err error
		for _, credential := range vcs {
			mapping, err = matchDescriptor(*inputDescriptor, credential)
			if err != nil {
				return PresentationSubmission{}, nil, err
			}
			if mapping != nil {
				mapping.Path = fmt.Sprintf("$.verifiableCredential[%d]", i)
				presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, *mapping)
				matchingCredentials = append(matchingCredentials, credential)
				break
			}
		}
		if mapping == nil {
			return PresentationSubmission{}, []vc.VerifiableCredential{}, nil
		}
	}

	return presentationSubmission, matchingCredentials, nil
}

func matchDescriptor(descriptor InputDescriptor, credential vc.VerifiableCredential) (*InputDescriptorMappingObject, error) {
	match, err := matchCredential(descriptor, credential)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, nil
	}

	return &InputDescriptorMappingObject{
		Id:     descriptor.Id,
		Format: "ldp_vc", // todo: hardcoded for now, must be derived from the VC
	}, nil
}

func matchCredential(descriptor InputDescriptor, credential vc.VerifiableCredential) (bool, error) {
	// for each constraint in descriptor.constraints:
	//   a vc must match the constraint
	if descriptor.Constraints != nil {
		return matchConstraint(descriptor.Constraints, credential)
	}
	return true, nil
}

func matchConstraint(constraint *Constraints, credential vc.VerifiableCredential) (bool, error) {
	// for each field in constraint.fields:
	//   a vc must match the field
	for _, field := range constraint.Fields {
		match, err := matchField(field, credential)
		if err != nil {
			return false, err
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}

func matchField(field Field, credential vc.VerifiableCredential) (bool, error) {
	// for each path in field.paths:
	//   a vc must match one of the path
	var optionalInvalid int
	for _, path := range field.Path {
		// if path is not found continue
		value, err := getValueAtPath(path, credential)
		if err != nil {
			return false, err
		}
		if value == nil {
			continue
		}
		// if filter at path matches return true
		if field.Filter != nil {
			match, err := matchFilter(*field.Filter, value)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
			// if filter at path does not match continue and set optionalInvalid
			optionalInvalid++
		}
	}
	// no matches, check optional. Optional is only valid if all paths returned no results
	// not if a filter did not match
	if field.Optional != nil && *field.Optional && optionalInvalid == 0 {
		return true, nil
	}
	return false, nil
}

// getValueAtPath uses the JSON path expression to get the value from the VC
func getValueAtPath(path string, vc vc.VerifiableCredential) (interface{}, error) {
	// first convert the VC back to JSON
	// then use the JSON path expression to get the value
	asJSON, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	var asInterface interface{}
	_ = json.Unmarshal(asJSON, &asInterface)

	return jsonpath.Get(path, asInterface)
}

// matchFilter matches the value against the filter.
// A filter is a JSON Schema descriptor (https://json-schema.org/draft/2020-12/json-schema-validation.html#name-a-vocabulary-for-structural)
// Supported schema types: string, number, boolean, array, enum.
// Supported schema properties: const, enum, pattern. These only work for strings.
// Supported go value types: string, float64, int, bool and array.
// 'null' values are also not supported.
// It returns an error on unsupported features or when the regex pattern fails.
func matchFilter(filter Filter, value interface{}) (bool, error) {
	// first we check if it's an enum, so we can recursively call matchFilter for each value
	if filter.Enum != nil {
		for _, enum := range *filter.Enum {
			f := Filter{
				Type:  "string",
				Const: &enum,
			}
			match, _ := matchFilter(f, value)
			if match {
				return true, nil
			}
		}
		return false, nil
	}

	switch value.(type) {
	case string:
		if filter.Type != "string" {
			return false, nil
		}
	case float64:
		if filter.Type != "number" {
			return false, nil
		}
	case int:
		if filter.Type != "number" {
			return false, nil
		}
	case bool:
		if filter.Type != "boolean" {
			return false, nil
		}
	case []interface{}:
		values := value.([]interface{})
		for _, v := range values {
			match, err := matchFilter(filter, v)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
	default:
		// object not supported for now
		return false, ErrUnsupportedFilter
	}

	if filter.Const != nil {
		if value != *filter.Const {
			return false, nil
		}
	}

	if filter.Pattern != nil && filter.Type == "string" {
		re, err := regexp2.Compile(*filter.Pattern, regexp2.ECMAScript)
		if err != nil {
			return false, err
		}
		return re.MatchString(value.(string))
	}

	return true, nil
}
