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
	"errors"
	"fmt"
	"github.com/PaesslerAG/jsonpath"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
	"strings"
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
	signInstructions := make([]SignInstruction, len(b.wallets))
	walletCredentialIndex := map[did.DID]int{}
	for j := range selectedVCs {
		for i, walletVCs := range b.wallets {
			for _, walletVC := range walletVCs {
				// do a JSON equality check
				if selectedVCs[j].Raw() == walletVC.Raw() {
					signInstructions[i].Holder = b.holders[i]
					signInstructions[i].VerifiableCredentials = append(signInstructions[i].VerifiableCredentials, selectedVCs[j])
					// remap the path to the correct wallet index
					mapping := inputDescriptorMappingObjects[j]
					mapping.Format = selectedVCs[j].Format()
					mapping.Path = fmt.Sprintf("$.verifiableCredential[%d]", walletCredentialIndex[b.holders[i]])
					signInstructions[i].Mappings = append(signInstructions[i].Mappings, mapping)
					walletCredentialIndex[b.holders[i]]++
				}
			}
		}
	}

	// filter out empty sign instructions
	nonEmptySignInstructions := make([]SignInstruction, 0)
	for _, signInstruction := range signInstructions {
		if !signInstruction.Empty() {
			nonEmptySignInstructions = append(nonEmptySignInstructions, signInstruction)
		}
	}

	index := 0
	// last we create the descriptor map for the presentation submission
	// If there's only one sign instruction the Path will be $.
	// If there are multiple sign instructions (each yielding a VP) the Path will be $[0], $[1], etc.
	for _, signInstruction := range nonEmptySignInstructions {
		if len(signInstruction.Mappings) > 0 {
			for _, inputDescriptorMapping := range signInstruction.Mappings {
				// If we have multiple VPs in the resulting submission, wrap each in a nested descriptor map (see path_nested in PEX specification).
				if len(nonEmptySignInstructions) > 1 {
					presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, InputDescriptorMappingObject{
						Id:         inputDescriptorMapping.Id,
						Format:     format,
						Path:       fmt.Sprintf("$[%d]", index),
						PathNested: &inputDescriptorMapping,
					})
				} else {
					// Just 1 VP, no nesting needed
					presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, inputDescriptorMapping)
				}
			}
			index++
		}
	}

	return presentationSubmission, nonEmptySignInstructions, nil
}

// Resolve returns a map where each of the input descriptors is mapped to the corresponding VerifiableCredential.
// If an input descriptor can't be mapped to a VC, an error is returned.
// This function is specified by https://identity.foundation/presentation-exchange/#processing-of-submission-entries
func (s PresentationSubmission) Resolve(envelope interface{}) (map[string]vc.VerifiableCredential, error) {
	switch envelope.(type) {
	case []interface{}:
		// list of VPs
	case map[string]interface{}:
		// single VP (JSON)
	case string:
		// single VP (JWT)
	default:
		return nil, errors.New("invalid Presentation Exchange envelope")
	}

	result := make(map[string]vc.VerifiableCredential)
	for _, inputDescriptor := range s.DescriptorMap {
		resolvedCredential, err := resolveCredential(nil, inputDescriptor, envelope)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve credential for input descriptor '%s': %w", inputDescriptor.Id, err)
		}
		result[inputDescriptor.Id] = *resolvedCredential
	}
	return result, nil
}

func resolveCredential(path []string, mapping InputDescriptorMappingObject, value interface{}) (*vc.VerifiableCredential, error) {
	fullPath := append(path, mapping.Path)
	fullPathString := strings.Join(fullPath, "/")

	targetValueRaw, err := jsonpath.Get(mapping.Path, value)
	if err != nil {
		return nil, fmt.Errorf("unable to get value for path %s: %w", fullPathString, err)
	}

	var decodedTargetValue interface{}
	switch targetValue := targetValueRaw.(type) {
	case string:
		// must be JWT VC or VP
		if mapping.Format == vc.JWTCredentialProofFormat {
			decodedTargetValue, err = vc.ParseVerifiableCredential(targetValue)
			if err != nil {
				return nil, fmt.Errorf("invalid JWT credential at path '%s': %w", fullPathString, err)
			}
		} else if mapping.Format == vc.JWTPresentationProofFormat {
			decodedTargetValue, err = vc.ParseVerifiablePresentation(targetValue)
			if err != nil {
				return nil, fmt.Errorf("invalid JWT presentation at path '%s': %w", fullPathString, err)
			}
		}
	case map[string]interface{}:
		// must be JSON-LD
		targetValueAsJSON, _ := json.Marshal(targetValue)
		if mapping.Format == vc.JSONLDCredentialProofFormat {
			decodedTargetValue, err = vc.ParseVerifiableCredential(string(targetValueAsJSON))
			if err != nil {
				return nil, fmt.Errorf("invalid JSON-LD credential at path '%s': %w", fullPathString, err)
			}
		} else if mapping.Format == vc.JSONLDPresentationProofFormat {
			decodedTargetValue, err = vc.ParseVerifiablePresentation(string(targetValueAsJSON))
			if err != nil {
				return nil, fmt.Errorf("invalid JSON-LD presentation at path '%s': %w", fullPathString, err)
			}
		}
	}
	if decodedTargetValue == nil {
		return nil, fmt.Errorf("value of Go type '%T' at path '%s' can't be decoded using format '%s'", targetValueRaw, fullPathString, mapping.Format)
	}
	if mapping.PathNested == nil {
		if decodedCredential, ok := decodedTargetValue.(*vc.VerifiableCredential); ok {
			return decodedCredential, nil
		}
		return nil, fmt.Errorf("path '%s' does not reference a credential", fullPathString)
	}
	// path_nested implies the credential is not found at the evaluated JSON path, but further down.
	// We need to decode the value at the path (could be a credential or presentation in JWT or VP format) and evaluate the nested path.
	decodedValueJSON, _ := json.Marshal(decodedTargetValue)
	var decodedValueMap map[string]interface{}
	_ = json.Unmarshal(decodedValueJSON, &decodedValueMap)
	return resolveCredential(fullPath, *mapping.PathNested, decodedValueMap)
}

// Validate validates the Presentation Submission to the Verifiable Presentations and Presentation Definitions and returns the mapped credentials.
// The credentials will be returned as map with the InputDescriptor.Id as key.
// The Presentation Definitions are passed in the envelope, as specified by the PEX specification.
// It assumes credentials of the presentations only map in 1 way to the input descriptors.
func (s PresentationSubmission) Validate(envelope Envelope, definition PresentationDefinition) (map[string]vc.VerifiableCredential, error) {
	actualCredentials, err := s.Resolve(envelope.Interface)
	if err != nil {
		return nil, fmt.Errorf("resolve credentials from presentation submission: %w", err)
	}

	// Create a new presentation submission: the submission being validated should have the same input descriptor mapping.
	submissionBuilder := definition.PresentationSubmissionBuilder()
	for _, presentation := range envelope.Presentations {
		signer, err := credential.PresentationSigner(presentation)
		if err != nil {
			return nil, fmt.Errorf("unable to derive presentation signer: %w", err)
		}
		submissionBuilder.AddWallet(*signer, presentation.VerifiableCredential)
	}
	_, signInstructions, err := submissionBuilder.Build("")
	if err != nil {
		return nil, err
	}
	if len(signInstructions) == 0 {
		return nil, errors.New("presentation submission doesn't match presentation definition")
	}
	// Build a input descriptor -> credential map for comparison
	expectedCredentials := make(map[string]vc.VerifiableCredential)
	for _, signInstruction := range signInstructions {
		for i, mapping := range signInstruction.Mappings {
			expectedCredentials[mapping.Id] = signInstruction.VerifiableCredentials[i]
		}
	}
	if len(actualCredentials) != len(expectedCredentials) {
		return nil, fmt.Errorf("expected %d credentials, got %d", len(expectedCredentials), len(actualCredentials))
	}
	for inputDescriptorID, expectedCredential := range expectedCredentials {
		if actualCredentials[inputDescriptorID].Raw() != expectedCredential.Raw() {
			return nil, fmt.Errorf("incorrect mapping for input descriptor: %s", inputDescriptorID)
		}
	}
	return expectedCredentials, nil
}
