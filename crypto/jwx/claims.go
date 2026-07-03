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

package jwx

import "encoding/json"

// AsMap converts a JOSE object (a jwt.Token, jws/jwe Headers, or jwk.Key) to a map of its
// fields, keyed by their JSON member names.
//
// It replaces jwx v2's AsMap methods, which were removed in v3. Marshaling via JSON (rather
// than iterating keys and calling Get per field) is deliberate: v3's per-field Get returns an
// error for a null-valued member, whereas the JSON round-trip preserves null members as nil -
// matching v2's AsMap behaviour and avoiding rejection of otherwise-valid input.
func AsMap(joseObject any) (map[string]interface{}, error) {
	data, err := json.Marshal(joseObject)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
