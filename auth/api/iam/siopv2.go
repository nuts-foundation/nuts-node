/*
 * Copyright (C) 2023 Nuts community
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
