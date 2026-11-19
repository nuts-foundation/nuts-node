/*
 * Copyright (C) 2026 Nuts community
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

// This file decides which credential (or none) each input descriptor of a presentation definition gets.
//
// Convention: a constraints field with an id names a value. Within one presentation, the same id means the same
// value everywhere: when two input descriptors declare a field with the same id, the credentials selected for them
// must agree on that value. Strings, numbers and booleans are compared as text (see ScalarAsText); arrays and
// objects are compared as JSON; a scalar never equals an array or object.
//
// The selection keeps one map of field id to value:
//   - It starts with the external keys: values given from outside this presentation definition (the caller's
//     credential_selection, or values carried over from another presentation of the same request). Keys no input
//     descriptor declares are skipped.
//   - The candidates of an input descriptor are the credentials that match its constraints and format and that
//     agree with the map on every id the descriptor declares.
//   - Rounds: an input descriptor whose candidates all have the same values for its declared ids is decided: it
//     takes its first candidate and that candidate's values are added to the map, which filters every other
//     undecided input descriptor declaring those ids. All descriptors of a round are evaluated against the map as
//     it was at the start of the round, so the order of input descriptors does not matter. Rounds repeat until a
//     round decides nothing.
//   - Should two descriptors decided in the same round disagree on an id, no fully consistent choice exists. The
//     first of them in the order of the presentation definition keeps its credential (the same tie-break as for
//     open descriptors below); the others are not decided in that round, so the next round filters them against
//     the map. As their candidates all have the conflicting value, this leaves them without a credential. This
//     keeps alternatives working, e.g. two input descriptors of a pick rule that ask for the same credential in two
//     formats: one of them gets a credential, which is all the pick rule needs.
//     Only in this case does the order of the input descriptors matter for decided descriptors.
//   - When the rounds settle with input descriptors still open (their candidates differ in id values):
//     an open descriptor that declares an external key fails the match with ErrMultipleCredentials, as the caller
//     selected a value that leaves more than one choice; otherwise the first open descriptor (in the order of the
//     presentation definition) takes its first candidate, its values are added to the map, and the rounds
//     continue. There is no backtracking: if that pick leaves another descriptor without candidates, that
//     descriptor gets no credential. The caller can avoid this by selecting the value.
//   - A descriptor without candidates gets no credential. Whether that is acceptable is up to the submission
//     requirements (without them, every input descriptor needs a credential).
//
// Comparing a credential's value with the map:
//   - an external key is strict: the field must resolve to a scalar with the same text; an array, an object or a
//     field that did not resolve never matches it;
//   - a value that entered the map while matching agrees with a field that did not resolve (an optional field),
//     and otherwise only with an equal value: a scalar with the same text, or an array or object with the same
//     JSON encoding. A scalar and an array or object never agree.
//
// This is the same notion of agreement the receiving side applies to a presentation, so a presentation built this
// way is not rejected for disagreeing values. Every value that resolved (scalar, array or object) enters the map;
// a field that did not resolve adds nothing. For "same values" within one descriptor, a field that did not resolve
// is a state of its own, and arrays and objects are compared as JSON.
//
// Without any field ids, or when no id is shared and there are no external keys, every input descriptor simply
// gets its first matching credential.
//
// Worked example. The wallet holds, in this order:
//
//	P1: provider credential, ura=1      D1: delegation, ura=1, employee=e1
//	P2: provider credential, ura=2      D2: delegation, ura=2, employee=e1
//
// The presentation definition asks for "provider" (declares id ura) and "delegation" (declares ura and
// employee), and the caller selects ura=2.
//   - The map starts as {ura: 2} (external). Candidates: provider [P2], delegation [D2].
//   - Round 1: both descriptors have one candidate, so both are decided: provider takes P2, delegation takes D2.
//     The map becomes {ura: 2, employee: e1}. Round 2 decides nothing: done.
//
// Without the caller's selection, the map starts empty: provider [P1, P2] and delegation [D1, D2] are both open.
// The first open descriptor (provider) takes P1, adding ura=1. The next round filters the delegation to [D1],
// which is then decided. The delegation follows the provider, whichever is picked.
//
// Cost: every (input descriptor, credential) pair is matched once. Each round or pick settles at least one input
// descriptor, so with n input descriptors, m credentials and k ids per descriptor, the loop takes O(n * n * m * k)
// comparisons on top of the n * m constraint matches.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nuts-foundation/go-did/vc"
)

// selectedValue is an entry in the map of field id to value, and the comparable form of a value a field resolved to.
type selectedValue struct {
	// text is the text of a scalar (see ScalarAsText), or the JSON encoding of an array or object.
	text string
	// nonScalar is true for an array or object, so a scalar whose text looks like JSON never equals it.
	nonScalar bool
	// external is true for a value given from outside the presentation definition, which is compared strictly.
	// External values are always scalars.
	external bool
}

// resolvedValue returns the comparable form of a value a field resolved to, or false when the field did not resolve.
// Arrays and objects are encoded as JSON; encoding/json writes object keys sorted, so equal values encode equally.
func resolvedValue(value interface{}) (selectedValue, bool) {
	if value == nil {
		return selectedValue{}, false
	}
	if text, isScalar := ScalarAsText(value); isScalar {
		return selectedValue{text: text}, true
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		// Values come from decoded JSON, so this does not happen; such a value then never equals anything.
		return selectedValue{text: fmt.Sprintf("unencodable %T", value), nonScalar: true}, true
	}
	return selectedValue{text: string(encoded), nonScalar: true}, true
}

// sameValue reports whether two entries hold the same value, ignoring where they came from.
func (v selectedValue) sameValue(other selectedValue) bool {
	return v.nonScalar == other.nonScalar && v.text == other.text
}

// descriptorMatch is a credential that matches an input descriptor, together with the comparable form of the values
// its fields with an id resolved to. An id whose field did not resolve (an optional field) is absent from values.
type descriptorMatch struct {
	credential vc.VerifiableCredential
	values     map[string]selectedValue
}

// descriptorSelection tracks one input descriptor while credentials are selected.
type descriptorSelection struct {
	descriptor *InputDescriptor
	// ids are the field ids the descriptor declares, sorted.
	ids []string
	// externalIDs are the ids the descriptor declares that have an external key, sorted.
	externalIDs []string
	// candidates are the matching credentials that still agree with the map, in wallet order.
	candidates []descriptorMatch
	// settled is true when the descriptor has a credential (selected) or has none left (selected is nil).
	settled  bool
	selected *descriptorMatch
	// unfulfilledReason explains why a descriptor that had matching credentials ended without one.
	unfulfilledReason string
}

// selectCredentials decides which credential each input descriptor gets, as described at the top of this file.
// It returns one Candidate per input descriptor, in the order of the presentation definition; a Candidate without
// VC means the input descriptor is not fulfilled. The second return value has, at the same position, an explanation
// for an input descriptor that had matching credentials that were all filtered out (empty otherwise).
// It returns an error for ErrMultipleCredentials, for a presentation definition that contains an empty (null)
// input descriptor, and for errors while matching a credential (e.g. a faulty JSON path or regex pattern, or a
// credential that cannot be converted to JSON).
func (presentationDefinition PresentationDefinition) selectCredentials(vcs []vc.VerifiableCredential, selection map[string]string, submitted map[string]vc.VerifiableCredential) ([]Candidate, []string, error) {
	values := make(map[string]selectedValue)
	descriptors := make([]*descriptorSelection, 0, len(presentationDefinition.InputDescriptors))
	for i, inputDescriptor := range presentationDefinition.InputDescriptors {
		if inputDescriptor == nil {
			// A null entry (e.g. in a presentation definition from a remote party) cannot be fulfilled or mapped.
			return nil, nil, fmt.Errorf("input descriptor at index %d of the presentation definition is empty", i)
		}
		matches, err := presentationDefinition.matchInputDescriptor(*inputDescriptor, restrictToSubmitted(inputDescriptor.Id, vcs, submitted))
		if err != nil {
			return nil, nil, err
		}
		current := &descriptorSelection{descriptor: inputDescriptor, ids: declaredFieldIDs(*inputDescriptor), candidates: matches}
		for _, id := range current.ids {
			if value, ok := selection[id]; ok {
				values[id] = selectedValue{text: value, external: true}
				current.externalIDs = append(current.externalIDs, id)
			}
		}
		descriptors = append(descriptors, current)
	}

	for {
		decideInRounds(descriptors, values)
		var open []*descriptorSelection
		for _, current := range descriptors {
			if !current.settled {
				open = append(open, current)
			}
		}
		if len(open) == 0 {
			break
		}
		for _, current := range open {
			if len(current.externalIDs) > 0 {
				return nil, nil, fmt.Errorf("input descriptor '%s': %w: credentials matching the selected field id(s) %s differ on field id(s) %s",
					current.descriptor.Id, ErrMultipleCredentials, strings.Join(current.externalIDs, ", "), strings.Join(current.differingFieldIDs(), ", "))
			}
		}
		// Nothing certain is left: the first open input descriptor takes its first candidate.
		open[0].selectFirstCandidate(values)
	}

	result := make([]Candidate, len(descriptors))
	reasons := make([]string, len(descriptors))
	for i, current := range descriptors {
		result[i] = Candidate{InputDescriptor: *current.descriptor}
		if current.selected != nil {
			credential := current.selected.credential
			result[i].VC = &credential
		} else {
			reasons[i] = current.unfulfilledReason
		}
	}
	return result, reasons, nil
}

// decideInRounds decides every input descriptor whose candidates all have the same id values, until a round
// decides nothing. Every descriptor in a round is evaluated against the values as they were at the start of the
// round, so which descriptors are decided does not depend on the order of the input descriptors.
func decideInRounds(descriptors []*descriptorSelection, values map[string]selectedValue) {
	for {
		var decided []*descriptorSelection
		for _, current := range descriptors {
			if current.settled {
				continue
			}
			current.filterCandidates(values)
			if current.settled {
				continue
			}
			if len(current.differingFieldIDs()) == 0 {
				decided = append(decided, current)
			}
		}
		if len(decided) == 0 {
			return
		}
		// Take the decided descriptors in the order of the presentation definition. One that disagrees with a value
		// added earlier in this round (two decided descriptors conflict) is not decided now: the next round filters
		// it against the map. The first one always agrees, as it was filtered against the map at the start of the
		// round, so every round settles at least one input descriptor and the loop ends.
		for _, current := range decided {
			if len(current.disagreeingFieldIDs(current.candidates[0], values)) > 0 {
				continue
			}
			current.selectFirstCandidate(values)
		}
	}
}

// filterCandidates removes the candidates that do not agree with values. When none is left, the input descriptor
// is settled without a credential.
func (d *descriptorSelection) filterCandidates(values map[string]selectedValue) {
	var remaining []descriptorMatch
	disagreeing := make(map[string]bool)
	for _, candidate := range d.candidates {
		ids := d.disagreeingFieldIDs(candidate, values)
		if len(ids) == 0 {
			remaining = append(remaining, candidate)
		}
		for _, id := range ids {
			disagreeing[id] = true
		}
	}
	d.candidates = remaining
	if len(remaining) > 0 {
		return
	}
	d.settled = true
	if len(disagreeing) > 0 {
		// It had matching credentials, but none agrees with the values selected so far.
		d.unfulfilledReason = fmt.Sprintf("no matching credential has the selected value for field id(s) %s", strings.Join(sortedKeys(disagreeing), ", "))
	}
}

// selectFirstCandidate gives the input descriptor its first candidate and adds every value that resolved on that
// candidate to values. The candidate agrees with values, so this never changes a value that is already there.
func (d *descriptorSelection) selectFirstCandidate(values map[string]selectedValue) {
	d.selected = &d.candidates[0]
	d.settled = true
	for id, value := range d.selected.values {
		if _, exists := values[id]; !exists {
			values[id] = value
		}
	}
}

// disagreeingFieldIDs returns the ids, sorted, on which the candidate disagrees with values.
// A field that did not resolve disagrees only with an external value (external values are strict); a field that
// resolved disagrees with any value that is not equal (see selectedValue.sameValue).
func (d *descriptorSelection) disagreeingFieldIDs(candidate descriptorMatch, values map[string]selectedValue) []string {
	var result []string
	for _, id := range d.ids {
		selected, ok := values[id]
		if !ok {
			continue
		}
		value, resolved := candidate.values[id]
		if !resolved && selected.external || resolved && !value.sameValue(selected) {
			result = append(result, id)
		}
	}
	return result
}

// differingFieldIDs returns the ids, sorted, for which not all candidates have the same value.
// A field that did not resolve differs from every value.
func (d *descriptorSelection) differingFieldIDs() []string {
	var result []string
	if len(d.candidates) == 0 {
		return result
	}
	for _, id := range d.ids {
		first, firstResolved := d.candidates[0].values[id]
		for _, other := range d.candidates[1:] {
			value, resolved := other.values[id]
			if resolved != firstResolved || resolved && !value.sameValue(first) {
				result = append(result, id)
				break
			}
		}
	}
	return result
}

// restrictToSubmitted returns the credentials an input descriptor may select from. Without submitted (when building
// a presentation) that is all of vcs. When validating a presentation submission, submitted maps input descriptor ids
// to the credentials the submission maps them to; an input descriptor that the submission maps may then only select
// that credential (compared by Raw(), as PresentationSubmission.Validate compares the outcome), and an input
// descriptor the submission does not map gets no candidate. Exactly the stated mapping is validated: were unmapped
// input descriptors free to select a presented credential, their selection could steer the agreement loop
// differently than on the holder (e.g. win a tie-break the holder never saw) and reject a valid presentation.
func restrictToSubmitted(inputDescriptorID string, vcs []vc.VerifiableCredential, submitted map[string]vc.VerifiableCredential) []vc.VerifiableCredential {
	if submitted == nil {
		return vcs
	}
	submittedCredential, mapped := submitted[inputDescriptorID]
	if !mapped {
		return nil
	}
	var result []vc.VerifiableCredential
	for _, credential := range vcs {
		if credential.Raw() == submittedCredential.Raw() {
			result = append(result, credential)
		}
	}
	return result
}

// matchInputDescriptor returns the credentials that match the constraints and format of the input descriptor,
// in the given order, with the comparable form of the values of the fields with an id.
func (presentationDefinition PresentationDefinition) matchInputDescriptor(inputDescriptor InputDescriptor, vcs []vc.VerifiableCredential) ([]descriptorMatch, error) {
	var matches []descriptorMatch
	for _, credential := range vcs {
		isMatch, fieldValues, err := matchCredential(inputDescriptor, credential)
		if err != nil {
			return nil, err
		}
		// InputDescriptor formats must be a subset of the PresentationDefinition formats, so it must satisfy both.
		if !isMatch || !matchFormat(presentationDefinition.Format, credential) || !matchFormat(inputDescriptor.Format, credential) {
			continue
		}
		values := make(map[string]selectedValue, len(fieldValues))
		for id, fieldValue := range fieldValues {
			if value, resolved := resolvedValue(fieldValue); resolved {
				values[id] = value
			}
		}
		matches = append(matches, descriptorMatch{credential: credential, values: values})
	}
	return matches, nil
}

// declaredFieldIDs returns the ids of the constraints fields of the input descriptor, sorted and without duplicates.
func declaredFieldIDs(inputDescriptor InputDescriptor) []string {
	ids := make(map[string]bool)
	if inputDescriptor.Constraints != nil {
		for _, field := range inputDescriptor.Constraints.Fields {
			if field.Id != nil {
				ids[*field.Id] = true
			}
		}
	}
	return sortedKeys(ids)
}

func sortedKeys(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
