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
