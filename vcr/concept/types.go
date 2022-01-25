/*
 * Nuts node
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

package concept

import (
	"encoding/json"
	"errors"

	"github.com/tidwall/gjson"
)

// ErrUnknownConcept is returned when an unknown concept is requested
var ErrUnknownConcept = errors.New("unknown concept")

// ErrNoType is returned when a template is loaded which doesn't have a type
var ErrNoType = errors.New("no template type found")

// ErrIncorrectType is returned when a requested value type is different tham the set type.
var ErrIncorrectType = errors.New("set value is not of correct type")

// ErrNoValue is returned when a requested path doesn't have a value.
var ErrNoValue = errors.New("no value for given path")

// Concept is a JSON format for querying and returning results of queries.
// It contains the default values of a VC: id, type, issuer and subject as well as custom concept specific data.
type Concept map[string]interface{}

// TypeField defines the concept/VC JSON joinPath to a VC type
const TypeField = "type"

// IDField defines the concept/VC JSON joinPath to a VC ID
const IDField = "id"

// IssuerField defines the concept/VC JSON joinPath to a VC issuer
const IssuerField = "issuer"

// SubjectField defines the concept JSONPath to a VC subject
const SubjectField = "subject"

// GetString returns the value at the given path or nil if not found
func (c Concept) GetString(path string) (string, error) {
	conceptJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	result := gjson.GetBytes(conceptJSON, path)
	if !result.Exists() {
		return "", ErrNoValue
	}

	return result.String(), nil
}
