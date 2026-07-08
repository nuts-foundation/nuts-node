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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOauthParameters_get(t *testing.T) {
	params := oauthParameters{
		"string":         "value",
		"stringSlice":    []string{"value"},
		"interfaceSlice": []interface{}{"value"},
		"multiSlice":     []interface{}{"a", "b"},
		"nonStringSlice": []interface{}{1},
		"number":         1,
	}
	assert.Equal(t, "value", params.get("string"))
	assert.Equal(t, "value", params.get("stringSlice"))
	// JWT claims decoded from JSON (e.g. the "aud" claim via jwx.AsMap) arrive as []interface{}.
	assert.Equal(t, "value", params.get("interfaceSlice"))
	assert.Empty(t, params.get("multiSlice"))
	assert.Empty(t, params.get("nonStringSlice"))
	assert.Empty(t, params.get("number"))
	assert.Empty(t, params.get("absent"))
}
