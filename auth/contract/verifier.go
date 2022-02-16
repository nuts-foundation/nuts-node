/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
 */

package contract

import (
	"time"

	"github.com/nuts-foundation/go-did/vc"
)

// State contains the result of the verification. It van be VALID or INVALID. This makes it human readable.
type State string

const (
	// Valid is used to indicate a contract was valid on the time of testing
	Valid State = "VALID"
	// Invalid is used to indicate a contract was invalid on the time of testing
	Invalid State = "INVALID"
)

// VerifierType is the type for a specific verifier
type VerifierType string

// VPVerifier defines the interface needed to verify a VerifiablePresentation
type VPVerifier interface {
	// VerifyVP validates a verifiable presentation.
	// When the verifier could not handle the verifiable presentation, an error should be thrown.
	VerifyVP(vp vc.VerifiablePresentation, checkTime *time.Time) (VPVerificationResult, error)
}

// VPVerificationResult describes the result of a contract validation
// it abstracts the name of the disclosed attributes from the means.
// the access token for example uses "initials", "family_name", "prefix" and "email"
type VPVerificationResult interface {
	// Validity indicates if the Presentation is valid
	// It can contains the "VALID" or "INVALID" status.
	// Validators must only set the Validity to "VALID" if the whole VP, including the embedded
	// contract are valid at the given moment in time.
	Validity() State
	// VPType returns the the VP type like "NutsUziPresentation".
	VPType() string
	// DisclosedAttribute returns the attribute value used to sign this contract
	// returns empty string when not found
	DisclosedAttribute(key string) string
	// ContractAttribute returns the attribute value used to fill the contract
	// returns empty string when not found
	ContractAttribute(key string) string
	// DisclosedAttributes returns the attributes used to sign this contract
	DisclosedAttributes() map[string]string
	// ContractAttributes returns the attributes used to fill the contract
	ContractAttributes() map[string]string
}
