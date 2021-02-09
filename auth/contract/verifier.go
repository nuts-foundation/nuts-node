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

import "time"

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
	VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (*VPVerificationResult, error)
}

// VPType holds the type of the Verifiable Presentation. Based on the format an appropriate validator can be selected.
type VPType string

// SigningMeans holds the unique nuts name of the singing means.
type SigningMeans string

// VerifiablePresentationBase holds the basic fields for a VerifiableCredential
// todo: move or use lib
type VerifiablePresentationBase struct {
	Context []string `json:"@context"`
	Type    []VPType
}

// VerifiableCredentialContext is the v1 base context for VPs
// todo: move or use lib
const VerifiableCredentialContext = "https://www.w3.org/2018/credentials/v1"

// VerifiablePresentationType is used as one of the types for a VerifiablePresentation
// todo move
const VerifiablePresentationType = VPType("VerifiablePresentation")

// VerifiablePresentation represents a W3C Verifiable Presentation
type VerifiablePresentation interface {
}

// BaseVerifiablePresentation represents a W3C Verifiable Presentation with only its Type attribute
type BaseVerifiablePresentation struct {
	Context []string               `json:"@context"`
	Proof   map[string]interface{} `json:"proof"`
	Type    []VPType               `json:"type"`
}

// Proof represents the Proof part of a Verifiable Presentation
// specific verifiers may extend upon this Proof
type Proof struct {
	Type string `json:"type"`
}

// VPVerificationResult contains the result of a contract validation
type VPVerificationResult struct {
	// Validity indicates if the Presentation is valid
	// It can contains the "VALID" or "INVALID" status.
	// Validators must only set the Validity to "VALID" if the whole VP, including the embedded
	// contract are valid at the given moment in time.
	Validity State
	// VPType contains the the VP type like "NutsUziPresentation".
	VPType VPType
	// ContractID contains the identifier string of the signed contract message like: "EN:PractitionerLogin:v3"
	ContractID string
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string
}
