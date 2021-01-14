/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/jwk"
	errors2 "github.com/pkg/errors"
)

// MapToJwk transforms a Jwk in map structure to a Jwk Key. The map structure is a typical result from json deserialization.
func MapToJwk(jwkAsMap map[string]interface{}) (jwk.Key, error) {
	set, err := MapsToJwkSet([]map[string]interface{}{jwkAsMap})
	if err != nil {
		return nil, err
	}
	return set.Keys[0], nil
}

// MapsToJwkSet transforms JWKs in map structures to a JWK set, just like MapToJwk.
func MapsToJwkSet(maps []map[string]interface{}) (*jwk.Set, error) {
	set := &jwk.Set{Keys: make([]jwk.Key, len(maps))}
	for i, m := range maps {
		jwkBytes, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(jwkBytes)
		if err != nil {
			return nil, err
		}
		set.Keys[i] = key
	}
	return set, nil
}

// ValidateJWK tests whether the given map (all) can is a parsable representation of a JWK. If not, an error is returned.
// If nil is returned, all supplied maps are parsable as JWK.
func ValidateJWK(maps ...interface{}) error {
	var stringMaps []map[string]interface{}
	for _, currMap := range maps {
		keyAsMap, ok := currMap.(map[string]interface{})
		if !ok {
			return errors.New("invalid JWK, it is not map[string]interface{}")
		}
		stringMaps = append(stringMaps, keyAsMap)
	}
	if _, err := MapsToJwkSet(stringMaps); err != nil {
		return errors2.Wrap(err, "invalid JWK")
	}
	return nil
}

// deepCopyMap is needed since the jwkSet.extractMap consumes the contents
func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = deepCopyMap(vm)
		} else {
			cp[k] = v
		}
	}
	return cp
}

// JwkToMap transforms a Jwk key to a map. Can be used for json serialization
func JwkToMap(key jwk.Key) (map[string]interface{}, error) {
	return key.AsMap(context.Background())
}

// PemToJwk transforms pem to jwk for PublicKey
func PemToJwk(pub []byte) (jwk.Key, error) {
	pk, err := PemToPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return jwk.New(pk)
}
