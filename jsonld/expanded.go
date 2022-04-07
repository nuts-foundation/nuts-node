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

package jsonld

// Path is used to traverse an expanded JSON-LD document
// Its elements are IRIs
type Path []string

// NewPath creates a Path
func NewPath(IRIs ...string) Path {
	return IRIs
}

// IsEmpty returns true of no IRIs are in the list
func (p Path) IsEmpty() bool {
	return len(p) == 0
}

// Head returns the first IRI of the list or ""
func (p Path) Head() string {
	if len(p) == 0 {
		return ""
	}
	return p[0]
}

// Tail returns the last IRIs of the list or nil
func (p Path) Tail() Path {
	if len(p) <= 1 {
		return nil
	}
	return p[1:]
}

// Expanded represents a JSON-LD document in expanded form.
// The expanded form is ideal for traversing and finding values
type Expanded []interface{}

// ValueAt returns the value found when traversing the given path
// It looks at the @id, @value and @list field
func (e Expanded) ValueAt(path Path) []Scalar {
	return valuesFromSliceAtPath(e, path)
}

func valuesFromSliceAtPath(expanded []interface{}, path Path) []Scalar {
	result := make([]Scalar, 0)

	for _, sub := range expanded {
		switch typedSub := sub.(type) {
		case []interface{}:
			result = append(result, valuesFromSliceAtPath(typedSub, path)...)
		case map[string]interface{}:
			result = append(result, valuesFromMapAtPath(typedSub, path)...)
		case string:
			result = append(result, MustParseScalar(typedSub))
		case bool:
			result = append(result, MustParseScalar(typedSub))
		case float64:
			result = append(result, MustParseScalar(typedSub))
		}
	}

	return result
}

func valuesFromMapAtPath(expanded map[string]interface{}, path Path) []Scalar {
	// JSON-LD in expanded form either has @value, @id, @list or @set
	if path.IsEmpty() {
		if value, ok := expanded["@value"]; ok {
			return []Scalar{MustParseScalar(value)}
		}
		if id, ok := expanded["@id"]; ok {
			return []Scalar{MustParseScalar(id)}
		}
		if list, ok := expanded["@list"]; ok {
			castList := list.([]interface{})
			return valuesFromSliceAtPath(castList, path)
		}
	}

	if list, ok := expanded["@list"]; ok {
		castList := list.([]interface{})
		return valuesFromSliceAtPath(castList, path)
	}

	if value, ok := expanded[path.Head()]; ok {
		// the value should now be a slice
		next, ok := value.([]interface{})
		if !ok {
			return nil
		}
		return valuesFromSliceAtPath(next, path.Tail())
	}

	return nil
}
