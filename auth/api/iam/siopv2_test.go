package iam

import (
	"encoding/json"
	"testing"
)

func TestMarshalOpenIDMetadata(t *testing.T) {
	md := OpenIDMetadata{
		OAuthAuthorizationServerMetadata: OAuthAuthorizationServerMetadata{
			Issuer: "https://example.com",
		},
		SubjectTypesSupported: "public",
		ScopesSupported:       "openid",
	}
	js, _ := json.MarshalIndent(md, "", "  ")
	t.Log(string(js))
}
