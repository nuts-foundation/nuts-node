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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

type AccessToken struct {
	// DPoP is the proof-of-possession of the key for the DID of the entity requesting the access token.
	DPoP *dpop.DPoP `json:"dpop"`
	// Token is the access token
	Token string
	// Issuer and Subject of a token are always the same.
	Issuer string
	// TODO: should client_id be extracted to the PDPMap using the presentation definition?
	// ClientId is the DID of the entity requesting the access token. The Client needs to proof its id through proof-of-possession of the key for the DID.
	ClientId string
	// IssuedAt is the time the token is issued
	IssuedAt time.Time
	// Expiration is the time the token expires
	Expiration time.Time
	// Scope the token grants access to. Not necessarily the same as the requested scope
	Scope string
	// InputDescriptorConstraintIdMap maps the ID field of a PresentationDefinition input descriptor constraint to the value provided in the VPToken for the constraint.
	// The Policy Decision Point can use this map to make decisions without having to deal with PEX/VCs/VPs/SignatureValidation
	InputDescriptorConstraintIdMap map[string]any

	// additional fields to support unforeseen policy decision requirements

	// VPToken contains the VPs provided in the 'assertion' field of the s2s AT request.
	VPToken []VerifiablePresentation
	// PresentationSubmission as provided in the 'presentation_submission' field of the s2s AT request.
	PresentationSubmission *pe.PresentationSubmission
	// PresentationDefinition fulfilled to obtain the AT in the s2s flow.
	PresentationDefinition *pe.PresentationDefinition
}

// createAccessToken is used in both the s2s and openid4vp flows
func (r Wrapper) createAccessToken(issuer did.DID, issueTime time.Time, presentations []vc.VerifiablePresentation, submission *pe.PresentationSubmission, definition PresentationDefinition, scope string, credentialSubjectDID did.DID, credentialMap map[string]vc.VerifiableCredential, dpopToken *dpop.DPoP) (*oauth.TokenResponse, error) {
	fieldsMap, err := definition.ResolveConstraintsFields(credentialMap)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve Presentation Definition Constraints Fields: %w", err)
	}
	accessToken := AccessToken{
		DPoP:                           dpopToken,
		Token:                          crypto.GenerateNonce(),
		Issuer:                         issuer.String(),
		ClientId:                       credentialSubjectDID.String(),
		IssuedAt:                       issueTime,
		Expiration:                     issueTime.Add(accessTokenValidity),
		Scope:                          scope,
		VPToken:                        presentations,
		PresentationDefinition:         &definition,
		PresentationSubmission:         submission,
		InputDescriptorConstraintIdMap: fieldsMap,
	}
	err = r.accessTokenServerStore().Put(accessToken.Token, accessToken)
	if err != nil {
		return nil, fmt.Errorf("unable to store access token: %w", err)
	}
	expiresIn := int(accessTokenValidity.Seconds())
	tokenType := AccessTokenTypeDPoP
	if dpopToken == nil {
		tokenType = AccessTokenTypeBearer
	}
	return &oauth.TokenResponse{
		AccessToken: accessToken.Token,
		ExpiresIn:   &expiresIn,
		Scope:       &scope,
		TokenType:   tokenType,
	}, nil
}
