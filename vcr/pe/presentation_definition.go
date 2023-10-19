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
	"github.com/dlclark/regexp2"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/vc"
	"strings"
)

// ErrUnsupportedFilter is returned when a filter uses unsupported features.
var ErrUnsupportedFilter = errors.New("unsupported filter")

// Match is a struct that holds the result of a match between an input descriptor and a VC
// A non-matching VC also leads to a Match, but without a VC.
type Match struct {
	InputDescriptor InputDescriptor
	VC              *vc.VerifiableCredential
}

// Match matches the VCs against the presentation definition.
// It implements §5 of the Presentation Exchange specification (v2.x.x pre-Draft, 2023-07-29) (https://identity.foundation/presentation-exchange/#presentation-definition)
// It supports the following:
// - ldp_vc format
// - pattern, const and enum only on string fields
// - number, boolean, array and string JSON schema types
// - Submission Requirements Feature
// It doesn't do the credential search, this should be done before calling this function.
// The PresentationDefinition.Format should be altered/set if an envelope defines the supported format before calling.
// The resulting PresentationSubmission has paths that are relative to the matching VCs.
// The PresentationSubmission needs to be altered so the paths use "path_nested"s that are relative to the created VP.
// ErrUnsupportedFilter is returned when a filter uses unsupported features.
// Other errors can be returned for faulty JSON paths or regex patterns.
func (presentationDefinition PresentationDefinition) Match(vcs []vc.VerifiableCredential) (PresentationSubmission, []vc.VerifiableCredential, error) {
	if len(presentationDefinition.SubmissionRequirements) > 0 {
		return presentationDefinition.matchSubmissionRequirements(vcs)
	}
	return presentationDefinition.matchBasic(vcs)
}

func (presentationDefinition PresentationDefinition) matchConstraints(vcs []vc.VerifiableCredential) ([]Match, error) {
	var matches []Match
	for _, inputDescriptor := range presentationDefinition.InputDescriptors {
		match := Match{
			InputDescriptor: *inputDescriptor,
		}
		for _, credential := range vcs {
			isMatch, err := matchCredential(*inputDescriptor, credential)
			if err != nil {
				return nil, err
			}
			if isMatch && matchFormat(presentationDefinition.Format, credential) {
				match.VC = &credential
				break
			}
		}
		matches = append(matches, match)
	}
	return matches, nil
}

func (presentationDefinition PresentationDefinition) matchBasic(vcs []vc.VerifiableCredential) (PresentationSubmission, []vc.VerifiableCredential, error) {
	// for each VC in vcs:
	// for each descriptor in presentation_definition.descriptors:
	// for each constraint in descriptor.constraints:
	// for each field in constraint.fields:
	//   a vc must match the field
	presentationSubmission := PresentationSubmission{
		Id:           uuid.New().String(),
		DefinitionId: presentationDefinition.Id,
	}
	matches, err := presentationDefinition.matchConstraints(vcs)
	if err != nil {
		return PresentationSubmission{}, nil, err
	}
	var index int
	matchingCredentials := make([]vc.VerifiableCredential, len(matches))
	for _, match := range matches {
		if match.VC == nil {
			return PresentationSubmission{}, []vc.VerifiableCredential{}, nil
		}
		mapping := InputDescriptorMappingObject{
			Path: fmt.Sprintf("$.verifiableCredential[%d]", index),
		}
		presentationSubmission.DescriptorMap = append(presentationSubmission.DescriptorMap, mapping)
		matchingCredentials[index] = *match.VC
		index++
	}

	return presentationSubmission, matchingCredentials, nil
}

func (presentationDefinition PresentationDefinition) matchSubmissionRequirements(vcs []vc.VerifiableCredential) (PresentationSubmission, []vc.VerifiableCredential, error) {
	// first we use the constraint matching algorithm to get the matching credentials
	matches, err := presentationDefinition.matchConstraints(vcs)
	if err != nil {
		return PresentationSubmission{}, nil, err
	}

	// then we check the group constraints
	// for each 'group' in input_descriptor there must be a matching 'from' field in a submission requirement
	availableGroups := make(map[string]Group)
	for _, submissionRequirement := range presentationDefinition.SubmissionRequirements {
		for _, group := range submissionRequirement.Groups() {
			availableGroups[group] = Group{
				Name: group,
			}
		}
	}
	for _, group := range presentationDefinition.groups() {
		if _, ok := availableGroups[group.Name]; !ok {
			return PresentationSubmission{}, nil, fmt.Errorf("group %s is required but not available", group.Name)
		}
	}

	// now we know there are no missing groups, we can start matching the submission requirements
	// now we add each specific match to the correct group(s)
	for _, match := range matches {
		for _, group := range match.InputDescriptor.Group {
			current := availableGroups[group]
			current.Matches = append(current.Matches, match)
			availableGroups[group] = current
		}
	}

	presentationSubmission := PresentationSubmission{
		Id:           uuid.New().String(),
		DefinitionId: presentationDefinition.Id,
	}
	var selectedVCs []vc.VerifiableCredential

	// for each submission requirement:
	// we select the credentials that match the requirement
	// then we apply the rules and save the resulting credentials
	for _, submissionRequirement := range presentationDefinition.SubmissionRequirements {
		submissionRequirementVCs, err := submissionRequirement.match(availableGroups)
		if err != nil {
			return PresentationSubmission{}, nil, err
		}
		selectedVCs = append(selectedVCs, submissionRequirementVCs...)
	}

	// todo: we deduplicate the credentials

	return presentationSubmission, selectedVCs, nil
}

func (submissionRequirement SubmissionRequirement) match(availableGroups map[string]Group) ([]vc.VerifiableCredential, error) {
	if submissionRequirement.From != "" && len(submissionRequirement.FromNested) > 0 {
		return nil, fmt.Errorf("submission requirement (%s) contains both 'from' and 'from_nested'", submissionRequirement.Name)
	}

	if len(submissionRequirement.FromNested) > 0 {
		return submissionRequirement.fromNested(availableGroups)
	}
	return submissionRequirement.from(availableGroups)
}

func (submissionRequirement SubmissionRequirement) from(availableGroups map[string]Group) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([]vc.VerifiableCredential, 0)
	group := availableGroups[submissionRequirement.From]
	// different rules for 'all' and 'pick'
	switch submissionRequirement.Rule {
	case "all":
		// all means all matches in the group must be in the submission
		// if any of the Match has an empty VC, we return an empty submission
		for _, match := range group.Matches {
			if match.VC == nil {
				return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from the group", submissionRequirement.Name)
			}
			selectedVCs = append(selectedVCs, *match.VC)
		}
		return selectedVCs, nil
	case "pick":
		// pick means we need to pick one or more of the matches
		// count number of matches with VC
		var count int
		for _, match := range group.Matches {
			if match.VC != nil {
				count++
			}
		}
		// check count
		if submissionRequirement.Count != nil {
			if count < *submissionRequirement.Count {
				return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than requried (%d)", submissionRequirement.Name, count, *submissionRequirement.Count)
			}
			i := 0

			for _, match := range group.Matches {
				if match.VC != nil {
					selectedVCs = append(selectedVCs, *match.VC)
					i++
				}
				if i == *submissionRequirement.Count {
					break
				}
			}
			return selectedVCs, nil
		}
		// check min and max
		if submissionRequirement.Min != nil && count < *submissionRequirement.Min {
			return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than min (%d)", submissionRequirement.Name, count, *submissionRequirement.Min)
		}
		if submissionRequirement.Max != nil && count > *submissionRequirement.Max {
			return nil, fmt.Errorf("submission requirement (%s) has more matches (%d) than max (%d)", submissionRequirement.Name, count, *submissionRequirement.Max)
		}
		// take min if both min and max are set
		index := 0
		for _, match := range group.Matches {
			if match.VC != nil {
				selectedVCs = append(selectedVCs, *match.VC)
				index++
			}
			if index == *submissionRequirement.Max {
				break
			}
		}
		return selectedVCs, nil
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}

func (submissionRequirement SubmissionRequirement) fromNested(availableGroups map[string]Group) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([][]vc.VerifiableCredential, len(submissionRequirement.FromNested))
	for i, nested := range submissionRequirement.FromNested {
		vcs, err := nested.match(availableGroups)
		if err != nil {
			if submissionRequirement.Rule == "all" {
				// exit early
				return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from nested requirements", submissionRequirement.Name)
			}
			continue
		}
		selectedVCs[i] = vcs
	}
	switch submissionRequirement.Rule {
	case "all":
		var returnVCs []vc.VerifiableCredential
		for _, vcs := range selectedVCs {
			returnVCs = append(returnVCs, vcs...)
		}
		return returnVCs, nil
	case "pick":
		var returnVCs []vc.VerifiableCredential
		// pick means we need to pick one or more of the nested sets
		var count int
		for _, set := range selectedVCs {
			if len(set) > 0 {
				count++
			}
		}
		// check count
		if submissionRequirement.Count != nil {
			if count < *submissionRequirement.Count {
				return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than requried (%d)", submissionRequirement.Name, count, *submissionRequirement.Count)
			}
			i := 0
			for _, set := range selectedVCs {
				if len(set) > 0 {
					returnVCs = append(returnVCs, set...)
					i++
				}
				if i == *submissionRequirement.Count {
					break
				}
			}
			return returnVCs, nil
		}
		// check min and max
		if submissionRequirement.Min != nil && count < *submissionRequirement.Min {
			return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than min (%d)", submissionRequirement.Name, count, *submissionRequirement.Min)
		}
		if submissionRequirement.Max != nil && count > *submissionRequirement.Max {
			return nil, fmt.Errorf("submission requirement (%s) has more matches (%d) than max (%d)", submissionRequirement.Name, count, *submissionRequirement.Max)
		}
		// take max if both min and max are set
		index := 0
		for _, set := range selectedVCs {
			if len(set) > 0 {
				returnVCs = append(returnVCs, set...)
				index++
			}
			if index == *submissionRequirement.Max {
				break
			}
		}
		return returnVCs, nil
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}

// groups returns all the Matches with input descriptors and matching VCs.
// If no VC matches the input descriptor, the match is still returned.
// todo: how to add VC to the match? Use the VC list from basicMatch?
func (presentationDefinition PresentationDefinition) groups() []Group {
	groups := make(map[string]Group)
	for _, inputDescriptor := range presentationDefinition.InputDescriptors {
		for _, group := range inputDescriptor.Group {
			existing, ok := groups[group]
			if !ok {
				existing = Group{
					Name: group,
				}
			}
			existing.Matches = append(existing.Matches, Match{InputDescriptor: *inputDescriptor})
			groups[group] = existing
		}
	}
	var result []Group
	for _, group := range groups {
		result = append(result, group)
	}
	return result
}

// matchFormat checks if the credential matches the Format from the presentationDefinition.
// if one of format['ldp_vc'] or format['jwt_vc'] is present, the VC must match that format.
// If the VC is of the required format, the alg or proofType must also match.
// vp formats are ignored.
// This might not be fully interoperable, but the spec at https://identity.foundation/presentation-exchange/#presentation-definition is not clear on this.
func matchFormat(format *PresentationDefinitionClaimFormatDesignations, credential vc.VerifiableCredential) bool {
	if format == nil {
		return true
	}

	asMap := map[string]map[string][]string(*format)
	// we're only interested in the jwt_vc and ldp_vc formats
	if asMap["jwt_vc"] == nil && asMap["ldp_vc"] == nil {
		return true
	}

	// only ldp_vc supported for now
	if entry := asMap["ldp_vc"]; entry != nil {
		if proofTypes := entry["proof_type"]; proofTypes != nil {
			for _, proofType := range proofTypes {
				if matchProofType(proofType, credential) {
					return true
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

func matchDescriptor(descriptor InputDescriptor, credential vc.VerifiableCredential) (*InputDescriptorMappingObject, error) {
	match, err := matchCredential(descriptor, credential)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, nil
	}

	return &InputDescriptorMappingObject{
		Id:     descriptor.Id,
		Format: "ldp_vc", // todo: hardcoded for now, must be derived from the VC, but we don't support other VC types yet
	}, nil
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
	// for each field in constraint.fields:
	//   a vc must match the field
	for _, field := range constraint.Fields {
		match, err := matchField(field, credential)
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
func matchField(field Field, credential vc.VerifiableCredential) (bool, error) {
	// jsonpath works on interfaces, so convert the VC to an interface
	asJSON, _ := json.Marshal(credential)
	var asInterface interface{}
	_ = json.Unmarshal(asJSON, &asInterface)

	// for each path in field.paths:
	//   a vc must match one of the path
	var optionalInvalid int
	for _, path := range field.Path {
		// if path is not found continue
		value, err := getValueAtPath(path, asInterface)
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
	if err != nil && (strings.HasPrefix(err.Error(), "unknown key") || strings.HasPrefix(err.Error(), "unsupported value type")) {
		return nil, nil
	}
	return value, err
}

// matchFilter matches the value against the filter.
// A filter is a JSON Schema descriptor (https://json-schema.org/draft/2020-12/json-schema-validation.html#name-a-vocabulary-for-structural)
// Supported schema types: string, number, boolean, array, enum.
// Supported schema properties: const, enum, pattern. These only work for strings.
// Supported go value types: string, float64, int, bool and array.
// 'null' values are also not supported.
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
