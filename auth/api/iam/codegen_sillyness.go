package iam

import "encoding/json"

var _ json.Marshaler = IntrospectAccessToken200JSONResponse{}

func (r IntrospectAccessToken200JSONResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(TokenIntrospectionResponse(r))
}
