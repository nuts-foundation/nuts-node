/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package v1

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// DIDDocument is an alias
type DIDDocument = did.Document

// DIDDocumentMetadata is an alias
type DIDDocumentMetadata = resolver.DocumentMetadata

// VerificationMethod is an alias
type VerificationMethod = did.VerificationMethod

// DIDCreateRequest defines model for DIDCreateRequest.
type DIDCreateRequest struct {
	VerificationMethodRelationship

	// List of DIDs that can control the new DID Document. If selfControl = true and controllers is not empty,
	// the newly generated DID will be added to the list of controllers.
	Controllers *[]string `json:"controllers,omitempty"`

	// whether the generated DID Document can be altered with its own capabilityInvocation key.
	SelfControl *bool `json:"selfControl,omitempty"`
}

// VerificationMethodRelationship defines model for VerificationMethodRelationship.
type VerificationMethodRelationship struct {
	// indicates if the generated key pair can be used for assertions.
	AssertionMethod *bool `json:"assertionMethod,omitempty"`

	// indicates if the generated key pair can be used for authentication.
	Authentication *bool `json:"authentication,omitempty"`

	// indicates if the generated key pair can be used for capability delegations.
	CapabilityDelegation *bool `json:"capabilityDelegation,omitempty"`

	// indicates if the generated key pair can be used for altering DID Documents.
	// In combination with selfControl = true, the key can be used to alter the new DID Document.
	// Defaults to true when not given.
	// default: true
	CapabilityInvocation *bool `json:"capabilityInvocation,omitempty"`

	// indicates if the generated key pair can be used for Key agreements.
	KeyAgreement *bool `json:"keyAgreement,omitempty"`

	// KeyType is the type of key to generate.
	Type *ssi.KeyType `json:"verificationMethodType,omitempty"`
}

// ToFlags takes default key flags, and enabled/disables the flags which are set on the VerificationMethodRelationship,
// and the result is returned.
func (r VerificationMethodRelationship) ToFlags(defaults management.DIDKeyFlags) management.DIDKeyFlags {
	result := defaults
	result = withKeyFlag(result, management.AuthenticationUsage, r.Authentication)
	result = withKeyFlag(result, management.AssertionMethodUsage, r.AssertionMethod)
	result = withKeyFlag(result, management.CapabilityDelegationUsage, r.CapabilityDelegation)
	result = withKeyFlag(result, management.CapabilityInvocationUsage, r.CapabilityInvocation)
	result = withKeyFlag(result, management.KeyAgreementUsage, r.KeyAgreement)
	return result
}

// withKeyFlag enables/disables the given flag on the current flag value, depending on the supplied bool.
// - bool == nil: do nothing
// - bool == true: enable flag
// - bool == false: disable flag
func withKeyFlag(current, flag management.DIDKeyFlags, value *bool) management.DIDKeyFlags {
	switch {
	case value == nil: // no setting
		return current
	case *value: // true
		return current | flag
	default: // false
		return current &^ flag
	}
}
