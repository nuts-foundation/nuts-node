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

package uzi

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

// ContractFormat is the contract format type
const ContractFormat = contract.SigningMeans("uzi")

// VerifiablePresentationType contains the string used in the VerifiablePresentation type array to indicate the Uzi means
const VerifiablePresentationType = contract.VPType("NutsUziPresentation")

// Verifier implements the Verifier interface and verifies the VerifiablePresentations of the NutsUziPresentation type.
type Verifier struct {
	UziValidator services.VPProofValueParser
}

// verifiablePresentation is the NutsUziPresentation specific data structure and can be used for parsing and unmarshaling
type verifiablePresentation struct {
	contract.VerifiablePresentationBase
	Proof proof
}

// proof contains the uzi specific proof part of the Verifiable presentation of the NutsUziPresentation type
type proof struct {
	Type       string
	ProofValue string
}

// VerifyVP implements the verifiablePresentation Verifier interface. It can verify an Uzi VP.
// It checks the signature, the attributes and the contract.
// Returns the contract.VPVerificationResult or an error if something went wrong.
func (u Verifier) VerifyVP(rawVerifiablePresentation []byte, _ *time.Time) (*contract.VPVerificationResult, error) {

	presentation := verifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &presentation); err != nil {
		return nil, fmt.Errorf("could not parse raw verifiable presentation: %w", err)
	}

	if len(presentation.Proof.ProofValue) == 0 {
		return nil, errors.New("could not verify empty proof")
	}

	typeMatch := false
	for _, pType := range presentation.Type {
		if typeMatch {
			break
		}
		typeMatch = pType == VerifiablePresentationType
	}
	if !typeMatch {
		return nil, fmt.Errorf("could not verify this verification type: '%v', should contain type: %s", presentation.Type, VerifiablePresentationType)
	}

	signedToken, err := u.UziValidator.Parse(presentation.Proof.ProofValue)
	if err != nil {
		return nil, fmt.Errorf("could not verify verifiable presentation: could not parse the proof: %w", err)
	}
	if err := u.UziValidator.Verify(signedToken); err != nil {
		return &contract.VPVerificationResult{
			Validity: contract.Invalid,
		}, nil
	}

	disclosedAttributes, err := signedToken.SignerAttributes()
	if err != nil {
		return nil, fmt.Errorf("could not get disclosed attributes from signed contract: %w", err)
	}

	return &contract.VPVerificationResult{
		Validity:            contract.Valid,
		VPType:              VerifiablePresentationType,
		DisclosedAttributes: disclosedAttributes,
		ContractAttributes:  signedToken.Contract().Params,
	}, nil
}
