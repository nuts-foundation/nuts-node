/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"errors"
	"strings"
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

// SetValue sets the field value. A joinPath supports '.' syntax for nested values.
func (c Concept) SetValue(path string, val interface{}) {
	parts := strings.Split(path, ".")

	m := c

	for i, p := range parts {
		if i == len(parts)-1 {
			m[p] = val
			break
		}
		if _, ok := m[p]; !ok {
			m[p] = Concept{}
		}
		m = m[p].(Concept)
	}
}

// GetValue returns the value at the given path or nil if not found
func (c Concept) GetValue(path string) interface{} {
	parts := strings.Split(path, ".")

	current := c
	var returnValue interface{}

	for i, p := range parts {
		if i == len(parts)-1 {
			returnValue = current[p]
			break
		}
		if sub, ok := current[p]; ok {
			ok2 := false
			if current, ok2 = sub.(Concept); ok2 {
				continue
			}
		}
		break
	}

	return returnValue
}

// GetString returns the value as a string for the given path or an error if not found or if the value is not a string
func (c Concept) GetString(path string) (string, error) {
	val := c.GetValue(path)

	if val == nil {
		return "", ErrNoValue
	}

	stringValue, ok := val.(string)
	if !ok {
		return "", ErrIncorrectType
	}

	return stringValue, nil
}
