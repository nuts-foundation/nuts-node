/*
 * Copyright (C) 2026 Nuts community
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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// ErrConflictingFieldValues is returned when fields that share an id resolve to different values across the
// credentials of a presentation. A field id names one value, so a presentation in which one id has two different
// values does not tell which of them is meant. Callers receiving a presentation from another party should treat
// this as an error of that party (a client error), not as an internal failure.
var ErrConflictingFieldValues = errors.New("fields sharing an id resolve to different values")

// mergeFieldValues adds the id values resolved for one input descriptor (values) to result, checking that they agree
// with the values that earlier input descriptors resolved for the same ids. resolvedBy records which input descriptor
// set the value of each id in result, so a conflict can name both descriptors.
//
// The rules:
//   - an unresolved field (a nil value, from an optional field that is absent from the credential) agrees with any
//     value: it is skipped in the comparison and never overwrites a resolved value. The id is still added to result
//     (with a nil value) when no input descriptor resolves it, as callers may rely on its presence;
//   - two resolved values agree when fieldValuesEqual says so; otherwise an ErrConflictingFieldValues error is returned
//     naming the id and both input descriptors;
//   - when two values agree but differ in Go type (e.g. "1" and 1), the value that was added first is kept.
func mergeFieldValues(result map[string]interface{}, resolvedBy map[string]string, inputDescriptorID string, values map[string]interface{}) error {
	// Visit the ids in a fixed order, so that when several ids conflict the same one is reported every time.
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		value := values[id]
		current, exists := result[id]
		if value == nil {
			if !exists {
				result[id] = nil
			}
			continue
		}
		if current == nil {
			result[id] = value
			resolvedBy[id] = inputDescriptorID
			continue
		}
		if !fieldValuesEqual(current, value) {
			return fmt.Errorf("%w: field id '%s' in input descriptors '%s' and '%s'", ErrConflictingFieldValues, id, resolvedBy[id], inputDescriptorID)
		}
	}
	return nil
}

// fieldValuesEqual reports whether two resolved field values are the same value.
// Scalars (strings, numbers, booleans) are compared by their text form (see ScalarAsText), so the string "1" equals
// the number 1. Other values (arrays, objects) are equal when their JSON encodings are equal; encoding/json writes
// object keys in sorted order, so key order does not matter. A scalar never equals a non-scalar.
func fieldValuesEqual(a, b interface{}) bool {
	aText, aIsScalar := ScalarAsText(a)
	bText, bIsScalar := ScalarAsText(b)
	if aIsScalar || bIsScalar {
		return aIsScalar && bIsScalar && aText == bText
	}
	aJSON, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bJSON, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aJSON, bJSON)
}
