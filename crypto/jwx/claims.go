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

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ClaimsAsMap returns a JWT token's claims as a map, keyed by their JSON member names.
//
// It replaces jwx v2's token.AsMap, which was removed in v3. Marshaling via JSON (rather than
// iterating keys and calling Get per claim) is deliberate: v3's per-field Get returns an error
// for a null-valued claim, whereas the JSON round-trip preserves null claims as nil - matching
// v2's AsMap behaviour and avoiding rejection of otherwise-valid tokens.
//
// This is unsuitable for jws/jwe protected headers: a JSON round-trip flattens rich header
// values (e.g. the x5c certificate chain) into plain JSON types, breaking callers that expect
// the concrete Go types.
func ClaimsAsMap(token jwt.Token) (map[string]interface{}, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
