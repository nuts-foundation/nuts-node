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

package orm

import "github.com/nuts-foundation/go-did/did"

// DIDKeyFlags is a bitmask used for specifying for what purposes a key in a DID document can be used (a.k.a. Verification Method relationships).
type DIDKeyFlags uint

// Is returns whether the specified DIDKeyFlags is enabled.
func (k DIDKeyFlags) Is(other DIDKeyFlags) bool {
	return k&other > 0
}

const (
	// AssertionMethodUsage indicates if the generated key pair can be used for assertions.
	AssertionMethodUsage DIDKeyFlags = 1 << iota
	// AuthenticationUsage indicates if the generated key pair can be used for authentication.
	AuthenticationUsage
	// CapabilityDelegationUsage indicates if the generated key pair can be used for altering DID Documents.
	CapabilityDelegationUsage
	// CapabilityInvocationUsage indicates if the generated key pair can be used for capability invocations.
	CapabilityInvocationUsage
	// KeyAgreementUsage indicates if the generated key pair can be used for Key agreements.
	KeyAgreementUsage
)

func AssertionKeyUsage() DIDKeyFlags {
	return CapabilityInvocationUsage | AssertionMethodUsage | AuthenticationUsage | CapabilityDelegationUsage
}

func EncryptionKeyUsage() DIDKeyFlags {
	return KeyAgreementUsage
}

// verificationMethodToKeyFlags creates DIDKeyFlags for a did.VerificationMethod based on its usage in the did.Document.
func verificationMethodToKeyFlags(document did.Document, vm *did.VerificationMethod) DIDKeyFlags {
	var flags DIDKeyFlags
	if document.Authentication.FindByID(vm.ID) != nil {
		flags |= AuthenticationUsage
	}
	if document.AssertionMethod.FindByID(vm.ID) != nil {
		flags |= AssertionMethodUsage
	}
	if document.CapabilityDelegation.FindByID(vm.ID) != nil {
		flags |= CapabilityDelegationUsage
	}
	if document.CapabilityInvocation.FindByID(vm.ID) != nil {
		flags |= CapabilityInvocationUsage
	}
	if document.KeyAgreement.FindByID(vm.ID) != nil {
		flags |= KeyAgreementUsage
	}
	return flags
}
