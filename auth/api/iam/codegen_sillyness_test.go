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
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntrospectAccessToken200JSONResponse_MarshalJSON(t *testing.T) {
	// deepmap/oapi-codegen generates TokenIntrospectionResponse.MarshalJSON() function to support additionalProperties.
	// But, the type being marshalled (due to the Strict Server Interface) is IntrospectAccessToken200JSONResponse
	// which is a type definition for the TokenIntrospectionResponse type, which causes the custom MarshalJSON function to be ignored.
	// This, in turn, causes additionalProperties not to be marshalled.
	// The only way to circumvent this is to have IntrospectAccessToken200JSONResponse implement the json.Marshaler interface,
	// and have it call the TokenIntrospectionResponse.MarshalJSON() function.
	response := TokenIntrospectionResponse{AdditionalProperties: map[string]interface{}{
		"message": "hello",
	}}
	asJSON, _ := json.Marshal(IntrospectAccessToken200JSONResponse(response))
	assert.JSONEq(t, `{"active":false, "message":"hello"}`, string(asJSON))
}
