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

package pe

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
)

// ParsePresentationSubmission validates the given JSON and parses it into a PresentationSubmission.
// It returns an error if the JSON is invalid or doesn't match the JSON schema for a PresentationSubmission.
func ParsePresentationSubmission(raw []byte) (*PresentationSubmission, error) {
	enveloped := `{"presentation_submission":` + string(raw) + `}`
	if err := v2.Validate([]byte(enveloped), v2.PresentationSubmission); err != nil {
		return nil, err
	}
	var result PresentationSubmission
	err := json.Unmarshal(raw, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// PresentationSubmissionBuilder is a builder for PresentationSubmissions.
// Multiple presentation definitions can be added to the builder.
type PresentationSubmissionBuilder struct {
	holders                []did.DID
	presentationDefinition PresentationDefinition
	wallets                [][]vc.VerifiableCredential
}

// PresentationSubmissionBuilder returns a new PresentationSubmissionBuilder.
// A PresentationSubmissionBuilder can be used to create a PresentationSubmission with multiple wallets as input.
func (presentationDefinition PresentationDefinition) PresentationSubmissionBuilder() PresentationSubmissionBuilder {
	return PresentationSubmissionBuilder{
		presentationDefinition: presentationDefinition,
	}
}

// AddWallet adds credentials from a wallet that may be used to create the PresentationSubmission.
func (b *PresentationSubmissionBuilder) AddWallet(holder did.DID, vcs []vc.VerifiableCredential) *PresentationSubmissionBuilder {
	b.holders = append(b.holders, holder)
	b.wallets = append(b.wallets, vcs)
	return b
}

// SignInstruction is a list of Holder/VCs combinations that can be used to create a VerifiablePresentation.
// When using multiple wallets, the outcome of a PresentationSubmission might require multiple VPs.
type SignInstruction struct {
	// Holder contains the DID of the holder that should sign the VP.
	Holder did.DID
	// VerifiableCredentials contains the VCs that should be included in the VP.
	VerifiableCredentials []vc.VerifiableCredential
	// Mappings contains the Input Descriptor that are mapped by this SignInstruction.
	Mappings []InputDescriptorMappingObject
}

// Empty returns true if there are no VCs in the SignInstruction.
func (signInstruction SignInstruction) Empty() bool {
	return len(signInstruction.VerifiableCredentials) == 0
}

// SignInstructions is a list of SignInstruction.
type SignInstructions []SignInstruction

// Empty returns true if all SignInstructions are empty.
func (signInstructions SignInstructions) Empty() bool {
	for _, signInstruction := range []SignInstruction(signInstructions) {
		if !signInstruction.Empty() {
			return false
		}
	}
	return true
}

// Build creates a PresentationSubmission from the added wallets.
// The VP format is determined by the given format.
func (b *PresentationSubmissionBuilder) Build(format string) (PresentationSubmission, SignInstructions, error) {
	presentationSubmission := PresentationSubmission{
		Id:           uuid.New().String(),
		DefinitionId: b.presentationDefinition.Id,
	}

	// first we need to select the VCs from all wallets that match the presentation definition
	allVCs := make([]vc.VerifiableCredential, 0)
	for _, vcs := range b.wallets {
		allVCs = append(allVCs, vcs...)
	}

	selectedVCs, inputDescriptorMappingObjects, err := b.presentationDefinition.Match(allVCs)
	if err != nil {
		return presentationSubmission, nil, err
	}

	// next we need to map the selected VCs to the correct wallet
	// loop over all selected VCs and find the wallet that contains the VC
	// there will be at most len(b.wallets) sign instructions
	var signInstructions []SignInstruction
	for _, holderID := range b.holders {
		var signInstruction *SignInstruction
		// find VCs that need to be in this sign instruction/verifiable presentation
		for i, selectedVC := range selectedVCs {
			if b.isHolder(holderID, selectedVC) {
				if signInstruction == nil {
					signInstruction = &SignInstruction{
						Holder: holderID,
					}
				}
				// the path property would be incorrect if there's multiple presentations,
				// so remap the path to the correct index of the VC within the presentation that will be created (through sign instruction).
				mapping := inputDescriptorMappingObjects[i]
				mapping.Path = fmt.Sprintf("$.verifiableCredential[%d]", len(signInstruction.VerifiableCredentials))
				mapping.Format = selectedVC.Format()
				signInstruction.VerifiableCredentials = append(signInstruction.VerifiableCredentials, selectedVC)
				signInstruction.Mappings = append(signInstruction.Mappings, mapping)
			}
		}
		if signInstruction != nil {
			signInstructions = append(signInstructions, *signInstruction)
		}
	}

	presentationIndex := 0
	// last we create the descriptor map for the presentation submission
	// If there's only one sign instruction the Path will be $.
	// If there are multiple sign instructions (each yielding a VP) the Path will be $[0], $[1], etc.
	for _, signInstruction := range signInstructions {
		if len(signInstruction.Mappings) > 0 {
			for _, inputDescriptorMapping := range signInstruction.Mappings {
				// If we have multiple VPs in the resulting submission, wrap each in a nested descriptor map (see path_nested in PEX specification).
				if len(signInstructions) > 1 {
					presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, InputDescriptorMappingObject{
						Id:         inputDescriptorMapping.Id,
						Format:     format,
						Path:       fmt.Sprintf("$[%d]", presentationIndex),
						PathNested: &inputDescriptorMapping,
					})
				} else {
					// Just 1 VP, no nesting needed
					presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, inputDescriptorMapping)
				}
			}
			presentationIndex++
		}
	}

	return presentationSubmission, signInstructions, nil
}

// isHolder returns true if the wallet of the specified subject contains the given VC.
func (b *PresentationSubmissionBuilder) isHolder(subjectID did.DID, credential vc.VerifiableCredential) bool {
	for i, holder := range b.holders {
		if holder == subjectID {
			// find VC in slice
			for _, curr := range b.wallets[i] {
				if curr.Raw() == credential.Raw() {
					return true
				}
			}
		}
	}
	return false
}
