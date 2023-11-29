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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/dlclark/regexp2"
	"github.com/nuts-foundation/go-did/vc"
)

// ErrUnsupportedFilter is returned when a filter uses unsupported features.
var ErrUnsupportedFilter = errors.New("unsupported filter")

// Candidate is a struct that holds the result of a match between an input descriptor and a VC
// A non-matching VC also leads to a Candidate, but without a VC.
type Candidate struct {
	InputDescriptor InputDescriptor
	VC              *vc.VerifiableCredential
}

// PresentationContext is a helper struct to keep track of the index of the VP in the nested paths of a PresentationSubmission.
type PresentationContext struct {
	Index                  int
	PresentationSubmission *PresentationSubmission
}

// Match matches the VCs against the presentation definition. It returns the matching Verifiable Credentials and their mapping to the Presentation Definition.
// If the given credentials do not match the presentation definition, no credentials, mapping, or error is returned.
// It implements §5 of the Presentation Exchange specification (v2.x.x pre-Draft, 2023-07-29) (https://identity.foundation/presentation-exchange/#presentation-definition)
// It supports the following:
// - ldp_vc format
// - jwt_vc format
// - pattern, const and enum only on string fields
// - number, boolean, array and string JSON schema types
// - Submission Requirements Feature
// ErrUnsupportedFilter is returned when a filter uses unsupported features.
// Other errors can be returned for faulty JSON paths or regex patterns.
func (presentationDefinition PresentationDefinition) Match(vcs []vc.VerifiableCredential) ([]vc.VerifiableCredential, []InputDescriptorMappingObject, error) {
	var selectedVCs []vc.VerifiableCredential
	var descriptorMaps []InputDescriptorMappingObject
	var err error
	if len(presentationDefinition.SubmissionRequirements) > 0 {
		if descriptorMaps, selectedVCs, err = presentationDefinition.matchSubmissionRequirements(vcs); err != nil {
			return nil, nil, err
		}
	} else if descriptorMaps, selectedVCs, err = presentationDefinition.matchBasic(vcs); err != nil {
		return nil, nil, err
	}

	return selectedVCs, descriptorMaps, nil
}

func (presentationDefinition PresentationDefinition) matchConstraints(vcs []vc.VerifiableCredential) ([]Candidate, error) {
	var candidates []Candidate

	for _, inputDescriptor := range presentationDefinition.InputDescriptors {
		// we create an empty Candidate. If a VC matches, it'll be attached to the Candidate.
		// if no VC matches, the Candidate will have an nil VC which is detected later on for SubmissionRequirement rules.
		match := Candidate{
			InputDescriptor: *inputDescriptor,
		}
		for _, credential := range vcs {
			isMatch, err := matchCredential(*inputDescriptor, credential)
			if err != nil {
				return nil, err
			}
			// InputDescriptor formats must be a subset of the PresentationDefinition formats, so it must satisfy both.
			if isMatch && matchFormat(presentationDefinition.Format, credential) && matchFormat(inputDescriptor.Format, credential) {
				match.VC = &credential
				break
			}
		}
		candidates = append(candidates, match)
	}

	return candidates, nil
}

func (presentationDefinition PresentationDefinition) matchBasic(vcs []vc.VerifiableCredential) ([]InputDescriptorMappingObject, []vc.VerifiableCredential, error) {
	// do the constraints check
	candidates, err := presentationDefinition.matchConstraints(vcs)
	if err != nil {
		return nil, nil, err
	}
	matchingCredentials := make([]vc.VerifiableCredential, len(candidates))
	var descriptors []InputDescriptorMappingObject
	var index int
	for i, candidate := range candidates {
		// a constraint is not matched, return early
		// we do not raise an error here since SubmissionRequirements might specify a "pick" rule
		if candidate.VC == nil {
			return nil, []vc.VerifiableCredential{}, nil
		}
		// create the InputDescriptorMappingObject with the relative path
		mapping := InputDescriptorMappingObject{
			Id:     candidate.InputDescriptor.Id,
			Format: candidate.VC.Format(),
			Path:   fmt.Sprintf("$.verifiableCredential[%d]", index),
		}
		descriptors = append(descriptors, mapping)
		matchingCredentials[i] = *candidate.VC
		index++
	}

	return descriptors, matchingCredentials, nil
}

func (presentationDefinition PresentationDefinition) matchSubmissionRequirements(vcs []vc.VerifiableCredential) ([]InputDescriptorMappingObject, []vc.VerifiableCredential, error) {
	// first we use the constraint matching algorithm to get the matching credentials
	candidates, err := presentationDefinition.matchConstraints(vcs)
	if err != nil {
		return nil, nil, err
	}

	// then we check the group constraints
	// for each 'group' in input_descriptor there must be a matching 'from' field in a submission requirement
	// This is the "all groups must be present" check
	availableGroups := make(map[string]groupCandidates)
	for _, submissionRequirement := range presentationDefinition.SubmissionRequirements {
		for _, group := range submissionRequirement.groups() {
			availableGroups[group] = groupCandidates{
				Name: group,
			}
		}
	}
	for _, group := range presentationDefinition.groups() {
		if _, ok := availableGroups[group.Name]; !ok {
			return nil, nil, fmt.Errorf("group '%s' is required but not available", group.Name)
		}
	}

	// now we know there are no missing groups, we can start matching the SubmissionRequirements
	// now we add each specific match to the correct group(s)
	for _, match := range candidates {
		for _, group := range match.InputDescriptor.Group {
			current := availableGroups[group]
			current.Candidates = append(current.Candidates, match)
			availableGroups[group] = current
		}
	}

	// for each SubmissionRequirement:
	// we select the credentials that match the requirement
	// then we apply the rules and save the resulting credentials
	var selectedVCs []vc.VerifiableCredential
	for _, submissionRequirement := range presentationDefinition.SubmissionRequirements {
		submissionRequirementVCs, err := submissionRequirement.match(availableGroups)
		if err != nil {
			return nil, nil, err
		}
		selectedVCs = append(selectedVCs, submissionRequirementVCs...)
	}

	uniqueVCs := deduplicate(selectedVCs)

	// now we have the selected VCs, we can create the PresentationSubmission
	var index int
	var descriptors []InputDescriptorMappingObject
outer:
	for _, uniqueVC := range uniqueVCs {
		// we loop over the candidate VCs and find the one that matches the unique VC
		// for each match we create a InputDescriptorMappingObject which links the VC to the InputDescriptor from the PresentationDefinition
		for _, candidate := range candidates {
			if candidate.VC != nil && vcEqual(uniqueVC, *candidate.VC) {
				mapping := InputDescriptorMappingObject{
					Id:     candidate.InputDescriptor.Id,
					Format: candidate.VC.Format(),
					Path:   fmt.Sprintf("$.verifiableCredential[%d]", index),
				}
				descriptors = append(descriptors, mapping)
				index++
				continue outer
			}
		}
	}

	return descriptors, uniqueVCs, nil
}

// groups returns all the groupCandidates with input descriptors and matching VCs.
func (presentationDefinition PresentationDefinition) groups() []groupCandidates {
	groups := make(map[string]groupCandidates)
	for _, inputDescriptor := range presentationDefinition.InputDescriptors {
		for _, group := range inputDescriptor.Group {
			existing, ok := groups[group]
			if !ok {
				existing = groupCandidates{
					Name: group,
				}
			}
			existing.Candidates = append(existing.Candidates, Candidate{InputDescriptor: *inputDescriptor})
			groups[group] = existing
		}
	}
	var result []groupCandidates
	for _, group := range groups {
		result = append(result, group)
	}
	return result
}

// matchFormat checks if the credential matches the Format from the presentationDefinition.
// If the VC is of the required format, the alg or proofType must also match.
// vp formats are ignored.
// This might not be fully interoperable, but the spec at https://identity.foundation/presentation-exchange/#presentation-definition is not clear on this.
func matchFormat(format *PresentationDefinitionClaimFormatDesignations, credential vc.VerifiableCredential) bool {
	if format == nil || len(*format) == 0 {
		return true
	}

	asMap := map[string]map[string][]string(*format)
	switch credential.Format() {
	case vc.JSONLDCredentialProofFormat:
		if entry := asMap[vc.JSONLDCredentialProofFormat]; entry != nil {
			if proofTypes := entry["proof_type"]; proofTypes != nil {
				for _, proofType := range proofTypes {
					if matchProofType(proofType, credential) {
						return true
					}
				}
			}
		}
	case vc.JWTCredentialProofFormat:
		// Get signing algorithm used to sign the JWT
		message, _ := jws.ParseString(credential.Raw()) // can't really fail, JWT has been parsed before.
		signingAlgorithm, _ := message.Signatures()[0].ProtectedHeaders().Get(jws.AlgorithmKey)
		// Check that the signing algorithm is specified by the presentation definition
		if entry := asMap[vc.JWTCredentialProofFormat]; entry != nil {
			if supportedAlgorithms := entry[jws.AlgorithmKey]; supportedAlgorithms != nil {
				for _, supportedAlgorithm := range supportedAlgorithms {
					if signingAlgorithm == jwa.SignatureAlgorithm(supportedAlgorithm) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchProofType(proofType string, credential vc.VerifiableCredential) bool {
	proofs, _ := credential.Proofs()
	for _, p := range proofs {
		if string(p.Type) == proofType {
			return true
		}
	}
	return false
}

func matchCredential(descriptor InputDescriptor, credential vc.VerifiableCredential) (bool, error) {
	// for each constraint in descriptor.constraints:
	//   a vc must match the constraint
	if descriptor.Constraints != nil {
		return matchConstraint(descriptor.Constraints, credential)
	}
	return true, nil
}

// matchConstraint matches the constraint against the VC.
// All Fields need to match according to the Field rules.
// IsHolder, SameSubject, SubjectIsIssuer, Statuses are not supported for now.
// LimitDisclosure is not supported for now.
func matchConstraint(constraint *Constraints, credential vc.VerifiableCredential) (bool, error) {
	// jsonpath works on interfaces, so convert the VC to an interface
	var credentialAsMap map[string]interface{}
	var err error
	switch credential.Format() {
	case vc.JWTCredentialProofFormat:
		// JWT-VCs marshal to a JSON string, so marshal an alias to make sure we get a JSON object with the VC properties,
		// instead of a JWT string.
		type Alias vc.VerifiableCredential
		credentialAsMap, err = remarshalToMap(Alias(credential))
	case vc.JSONLDCredentialProofFormat:
		credentialAsMap, err = remarshalToMap(credential)
	}
	if err != nil {
		return false, err
	}

	// for each field in constraint.fields:
	//   a vc must match the field
	for _, field := range constraint.Fields {
		match, err := matchField(field, credentialAsMap)
		if err != nil {
			return false, err
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}

// matchField matches the field against the VC.
// All fields need to match unless optional is set to true and no values are found for all the paths.
func matchField(field Field, credential map[string]interface{}) (bool, error) {
	// for each path in field.paths:
	//   a vc must match one of the path
	var optionalInvalid int
	for _, path := range field.Path {
		// if path is not found continue
		value, err := getValueAtPath(path, credential)
		if err != nil {
			return false, err
		}
		if value == nil {
			continue
		}

		if field.Filter == nil {
			return true, nil
		}

		// if filter at path matches return true
		match, err := matchFilter(*field.Filter, value)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
		// if filter at path does not match continue and set optionalInvalid
		optionalInvalid++
	}
	// no matches, check optional. Optional is only valid if all paths returned no results
	// not if a filter did not match
	if field.Optional != nil && *field.Optional && optionalInvalid == 0 {
		return true, nil
	}
	return false, nil
}

// getValueAtPath uses the JSON path expression to get the value from the VC
func getValueAtPath(path string, vcAsInterface interface{}) (interface{}, error) {
	value, err := jsonpath.Get(path, vcAsInterface)
	// jsonpath.Get returns some errors if the path is not found, or it has a different type as expected
	if err != nil && (strings.HasPrefix(err.Error(), "unknown key") ||
		strings.HasPrefix(err.Error(), "unsupported value type") ||
		// Then a JSON path points to an array, but the expression doesn't specify an index
		strings.HasPrefix(err.Error(), "could not select value, invalid key: expected number but got")) {
		return nil, nil
	}
	return value, err
}

// matchFilter matches the value against the filter.
// A filter is a JSON Schema descriptor (https://json-schema.org/draft/2020-12/json-schema-validation.html#name-a-vocabulary-for-structural)
// Supported schema types: string, number, boolean, array, enum.
// Supported schema properties: const, enum, pattern. These only work for strings.
// Supported go value types: string, float64, int, bool and array.
// 'null' values are not supported.
// It returns an error on unsupported features or when the regex pattern fails.
func matchFilter(filter Filter, value interface{}) (bool, error) {
	// first we check if it's an enum, so we can recursively call matchFilter for each value
	if filter.Enum != nil {
		for _, enum := range filter.Enum {
			f := Filter{
				Type:  "string",
				Const: &enum,
			}
			match, _ := matchFilter(f, value)
			if match {
				return true, nil
			}
		}
		return false, nil
	}

	switch value.(type) {
	case string:
		if filter.Type != "string" {
			return false, nil
		}
	case float64:
		if filter.Type != "number" {
			return false, nil
		}
	case int:
		if filter.Type != "number" {
			return false, nil
		}
	case bool:
		if filter.Type != "boolean" {
			return false, nil
		}
	case []interface{}:
		values := value.([]interface{})
		for _, v := range values {
			match, err := matchFilter(filter, v)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
	default:
		// object not supported for now
		return false, ErrUnsupportedFilter
	}

	if filter.Const != nil {
		if value != *filter.Const {
			return false, nil
		}
	}

	if filter.Pattern != nil && filter.Type == "string" {
		re, err := regexp2.Compile(*filter.Pattern, regexp2.ECMAScript)
		if err != nil {
			return false, err
		}
		return re.MatchString(value.(string))
	}

	// if we get here, no pattern, enum or const is requested just the type.
	return true, nil
}

// deduplicate removes duplicate VCs from the slice.
// It uses JSON marshalling to determine if two VCs are equal.
func deduplicate(vcs []vc.VerifiableCredential) []vc.VerifiableCredential {
	var result []vc.VerifiableCredential
	for _, vc := range vcs {
		found := false
		for _, existing := range result {
			if vcEqual(existing, vc) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, vc)
		}
	}
	return result
}

// vcEqual checks if two VCs are equal.
// It uses JSON marshalling to determine if two VCs are equal.
func vcEqual(a, b vc.VerifiableCredential) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

func remarshal(src interface{}, dst interface{}) error {
	asJSON, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(asJSON, &dst)
}

func remarshalToMap(v interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := remarshal(v, &result); err != nil {
		return nil, err
	}
	return result, nil
}
