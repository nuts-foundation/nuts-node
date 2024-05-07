/*
 * Copyright (C) 2024 Nuts community
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

package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

// main reads 2 YAML files, then merges the "paths" and "components" object from file 2 into file 1.
// - paths can only exist in file 1 or file 2, not in both (otherwise an error is returned)
// - components.schemas can exist in both files, but those from file 2 overwrite those from file 1 (required because 1 and 2 share the same types).
// It is used to combine 2 OpenAPI specification files.
// There are of course existing tools that can do this, but the ones I found were:
// - not in Go (but e.g. npm, which we don't want in this project)
// - not maintained
// So instead of adding a risk of an external (unsafe) build tool, we have our own simple fit-for-purpose version.
func main() {
	if len(os.Args) != 3 {
		panic("Usage: go run main.go <input-file-1> <input-file-2>")
	}

	inputFile1 := os.Args[1]
	inputFile2 := os.Args[2]

	// Read the 2 YAML files, then merge the "paths" and "components" object from file 2 into file 1
	// Write the result to STDOUT

	// Example:
	// $ go run main.go file1.yaml file2.yaml > merged.yaml

	// Read the 2 YAML files
	file1Data, err := os.ReadFile(inputFile1)
	if err != nil {
		panic("Error reading file 1: " + err.Error())
	}
	file2Data, err := os.ReadFile(inputFile2)
	if err != nil {
		panic("Error reading file 2: " + err.Error())
	}
	result, err := merge(file1Data, file2Data)
	if err != nil {
		panic("Error merging files: " + err.Error())
	}
	println(string(result))
}

func merge(input1Data []byte, input2Data []byte) ([]byte, error) {
	var input1 map[string]interface{}
	if err := yaml.Unmarshal(input1Data, &input1); err != nil {
		return nil, fmt.Errorf("error unmarshalling input 1: %w", err)
	}
	var input2 map[string]interface{}
	if err := yaml.Unmarshal(input2Data, &input2); err != nil {
		return nil, fmt.Errorf("error unmarshalling input 2: %w", err)
	}
	// Merge the "paths" and "components" object from file 2 into file 1
	err := mergeObject(input1, input2, "paths", false)
	if err != nil {
		return nil, err
	}
	components1, err := objectAt(input1, "components")
	if err != nil {
		panic(err)
	}
	components2, err := objectAt(input2, "components")
	if err != nil {
		panic(err)
	}
	err = mergeObject(components1, components2, "schemas", true)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(input1)
}

func objectAt(input map[string]interface{}, path string) (map[string]interface{}, error) {
	value, ok := input[path].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("path %s not found", path)
	}
	return value, nil
}

func mergeObject(input1 map[string]interface{}, input2 map[string]interface{}, path string, overwrite bool) error {
	paths1, ok := input1[path].(map[string]interface{})
	if !ok {
		paths1 = make(map[string]interface{})
	}
	paths2, ok := input2[path].(map[string]interface{})
	if ok {
		for apiPath, definition := range paths2 {
			// if already exists in input 1, return error
			if !overwrite {
				if _, exists := paths1[apiPath]; exists {
					return fmt.Errorf("path %s already exists in input 1", apiPath)
				}
			}
			paths1[apiPath] = definition
		}
	}
	return nil
}
