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
	"fmt"
	"reflect"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/crypto"

	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

type AccessToken struct {
	// DPoP is the proof-of-possession of the key for the DID of the entity requesting the access token.
	DPoP *dpop.DPoP `json:"dpop"`
	// Token is the access token
	Token string `json:"token"`
	// Issuer and Subject of a token are always the same.
	Issuer string `json:"issuer"`
	// TODO: should client_id be extracted to the PDPMap using the presentation definition?
	// ClientId is the DID of the entity requesting the access token. The Client needs to proof its id through proof-of-possession of the key for the DID.
	ClientId string `json:"client_id"`
	// IssuedAt is the time the token is issued
	IssuedAt time.Time `json:"issued_at"`
	// Expiration is the time the token expires
	Expiration time.Time `json:"expiration"`
	// Scope the token grants access to. Not necessarily the same as the requested scope
	Scope string `json:"scope"`
	// InputDescriptorConstraintIdMap maps the ID field of a PresentationDefinition input descriptor constraint to the value provided in the VPToken for the constraint.
	// The Policy Decision Point can use this map to make decisions without having to deal with PEX/VCs/VPs/SignatureValidation
	InputDescriptorConstraintIdMap map[string]any `json:"inputdescriptor_constraint_id_map,omitempty"`

	// additional fields to support unforeseen policy decision requirements

	// VPToken contains the VPs provided in the 'assertion' field of the s2s AT request.
	VPToken []VerifiablePresentation `json:"vp_token,omitempty"`
	// PresentationSubmissions as provided in by the wallet to fulfill the required Presentation Definition(s).
	PresentationSubmissions map[string]pe.PresentationSubmission `json:"presentation_submissions,omitempty"`
	// PresentationDefinitions that were required by the verifier to fulfill the request.
	PresentationDefinitions pe.WalletOwnerMapping `json:"presentation_definitions,omitempty"`
}

// AddInputDescriptorConstraintIdMap adds the given map to the access token.
// If there are already values in the map, they MUST equal the new values, otherwise an error is returned.
// This is used for having claims from multiple access policies/presentation definitions in the same access token,
// while preventing conflicts between them (2 policies specifying the same credential ID field for different credentials).
func (a *AccessToken) AddInputDescriptorConstraintIdMap(claims map[string]any) error {
	if a.InputDescriptorConstraintIdMap == nil {
		a.InputDescriptorConstraintIdMap = make(map[string]any)
	}
	for k, v := range claims {
		if existing, ok := a.InputDescriptorConstraintIdMap[k]; ok {
			if !reflect.DeepEqual(existing, v) {
				return fmt.Errorf("conflicting values for input descriptor constraint id %s: existing value %v, new value %v", k, existing, v)
			}
		} else {
			a.InputDescriptorConstraintIdMap[k] = v
		}
	}
	return nil
}

// createAccessToken is used in both the s2s and openid4vp flows
func (r Wrapper) createAccessToken(issuerURL string, clientID string, issueTime time.Time, scope string, template AccessToken, dpopToken *dpop.DPoP) (*oauth.TokenResponse, error) {
	accessToken := template
	accessToken.DPoP = dpopToken
	accessToken.Token = crypto.GenerateNonce()
	accessToken.Issuer = issuerURL
	accessToken.IssuedAt = issueTime
	accessToken.ClientId = clientID
	accessToken.Expiration = issueTime.Add(accessTokenValidity)
	accessToken.Scope = scope

	err := r.accessTokenServerStore().Put(accessToken.Token, accessToken)
	if err != nil {
		return nil, fmt.Errorf("unable to store access token: %w", err)
	}
	expiresIn := int(accessTokenValidity.Seconds())
	tokenResponse := oauth.TokenResponse{
		AccessToken: accessToken.Token,
		ExpiresIn:   &expiresIn,
		Scope:       &scope,
		TokenType:   AccessTokenTypeBearer,
	}
	if dpopToken != nil {
		tokenResponse.TokenType = AccessTokenTypeDPoP
		tokenResponse.DPoPKid = to.Ptr(dpopToken.Kid)
	}
	return &tokenResponse, nil
}
