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
// For jws/jwe protected headers use HeadersAsMap instead: a JSON round-trip flattens rich header
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

// HeadersAsMap converts jws or jwe protected headers to a map of their members, keyed by JSON
// member name.
//
// Unlike AsMap it iterates the members with Get, preserving the concrete Go types of rich
// members such as the x5c certificate chain (a JSON round-trip would flatten those). It
// replaces jwx v2's Headers.AsMap: a null-valued member is stored as nil rather than causing an
// error, because v3's per-field Get fails on a null value and would otherwise reject an
// otherwise-valid header set.
func HeadersAsMap(headers interface {
	Keys() []string
	Get(string, any) error
}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, k := range headers.Keys() {
		var v interface{}
		if err := headers.Get(k, &v); err != nil {
			// k comes from Keys() so the member exists, and the destination is interface{},
			// which accepts any non-nil value; the only failure mode is a null-valued member.
			// Represent it as nil, matching v2's Headers.AsMap.
			result[k] = nil
			continue
		}
		result[k] = v
	}
	return result
}
