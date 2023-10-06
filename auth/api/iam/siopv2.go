package iam

import (
	"time"
)

type StandardClaims struct {
	Issuer         string    `json:"iss,omitempty"`
	Subject        string    `json:"sub,omitempty"`
	Audience       string    `json:"aud,omitempty"`
	ExpirationTime time.Time `json:"exp,omitempty"`
	IssuedAt       time.Time `json:"iat,omitempty"`
	NotBefore      time.Time `json:"nbf,omitempty"`
	JwtID          string    `json:"jti,omitempty"`
}

type OpenIDAuthorizationRequest struct {
	StandardClaims
	Nonce        string                           `json:"nonce,omitempty"`
	Registration OAuthAuthorizationServerMetadata `json:"registration,omitempty"`
}

type OpenIDRelyingPartyMetadata struct {
	OAuthAuthorizationServerMetadata
	SubjectTypesSupported string `json:"subject_types_supported,omitempty"` // TODO: isn't this only for the Provider?
	ScopesSupported       string `json:"scopes_supported,omitempty"`
}
