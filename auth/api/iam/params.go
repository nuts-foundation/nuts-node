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

package iam

import "net/url"

// oauthParameters is a helper for oauth params.
// oauth params can be derived from query params or JWT claims (RFC9101).
// in theory all params could be string, arrays or numbers. Our handlers only want single string values for all params.
// since empty values always lead to validation errors, the get method will return an empty value if the param is not present or has a wrong format.
// array values with len == 1 will be treated as single string values.
type oauthParameters map[string]interface{}

func parseQueryParams(values url.Values) oauthParameters {
	underlying := make(map[string]interface{})
	for key, value := range values {
		underlying[key] = value
	}
	return underlying
}

func parseJWTClaims(claims map[string]interface{}) oauthParameters {
	underlying := make(map[string]interface{})
	for key, value := range claims {
		underlying[key] = value
	}
	return underlying
}

// get returns the string value if present and if an actual string
// for arrays it'll return the first value if len == 1
// else it'll return an empty string
func (ssp oauthParameters) get(key string) string {
	value, ok := ssp[key]
	if !ok {
		return ""
	}
	switch typedValue := value.(type) {
	case string:
		return typedValue
	case []string:
		if len(typedValue) == 1 {
			return typedValue[0]
		}
	}
	return ""
}
