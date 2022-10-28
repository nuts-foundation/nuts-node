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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DIDDocument is an alias
type DIDDocument = did.Document

// DIDDocumentMetadata is an alias
type DIDDocumentMetadata = types.DocumentMetadata

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
}

// ToKeyUsage takes a default key usage, and enabled/disables the usage which is set on the VerificationMethodRelationship,
// and the result is returned.
func (r VerificationMethodRelationship) ToKeyUsage(defaults types.KeyUsage) types.KeyUsage {
	result := defaults
	result = setKeyUsage(result, r.Authentication, types.AuthenticationUsage)
	result = setKeyUsage(result, r.AssertionMethod, types.AssertionMethodUsage)
	result = setKeyUsage(result, r.CapabilityDelegation, types.CapabilityDelegationUsage)
	result = setKeyUsage(result, r.CapabilityInvocation, types.CapabilityInvocationUsage)
	result = setKeyUsage(result, r.KeyAgreement, types.KeyAgreementUsage)
	return result
}

func setKeyUsage(current types.KeyUsage, value *bool, keyUsageToSet types.KeyUsage) types.KeyUsage {
	// If not set, do nothing (keep existing value)
	// If set (may be true or false), disable or enable
	if value != nil {
		// Override default
		if *value {
			// Enable
			return current | keyUsageToSet
		}
		// Disable
		return current ^ keyUsageToSet
	}
	return current
}
