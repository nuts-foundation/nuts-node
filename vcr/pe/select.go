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

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nuts-foundation/go-did/vc"
)

// selectOptions holds the knobs configured by the Option functions passed to Select.
type selectOptions struct {
	// initialBindings seeds the id->value bindings (typically from a credential_selection parameter).
	initialBindings map[string]string
}

// Option configures a single Select call. Options exist so that callers can opt in to
// behaviour (initial bindings, strict ambiguity detection, tracing) without widening the
// Select signature for every new knob.
type Option func(*selectOptions)

// WithInitialBindings seeds the search with id->value bindings, constraining which candidates
// can fill the descriptors carrying those field ids. Keys that are not field ids on the PD have
// no effect.
func WithInitialBindings(b map[string]string) Option {
	return func(o *selectOptions) {
		o.initialBindings = b
	}
}

// Result is the outcome of a Select call.
type Result struct {
	// Candidates pairs every input descriptor (in PD order) with the VC chosen for it.
	// A nil VC means the descriptor was left unfilled (optional and skipped, or dropped by a rule).
	Candidates []Candidate
	// Bindings holds the resolved field-id to value pairs of the chosen assignment.
	Bindings map[string]string
}

// Select resolves a presentation definition against a set of candidate credentials and
// returns the chosen descriptor-to-VC assignment. It is the single matching engine: it
// matches each descriptor on its own, searches for a binding-consistent combination across
// descriptors, and applies the submission requirement rules.
func Select(pd PresentationDefinition, candidates []vc.VerifiableCredential, opts ...Option) (Result, error) {
	var options selectOptions
	for _, opt := range opts {
		opt(&options)
	}

	var result Result
	for _, descriptor := range pd.InputDescriptors {
		eligible, err := eligibleCandidates(pd, *descriptor, candidates)
		if err != nil {
			return result, err
		}
		// Keep only candidates whose resolved id-values agree with the bindings (P3 consistency).
		consistent := consistentCandidates(eligible, options.initialBindings)
		// A descriptor pinned by the caller's bindings must resolve to exactly one candidate.
		if len(consistent) > 1 && isCallerBound(*descriptor, options.initialBindings) {
			return result, fmt.Errorf("input descriptor '%s': %w", descriptor.Id, ErrMultipleCredentials)
		}
		var selected *vc.VerifiableCredential
		if len(consistent) > 0 {
			selected = &consistent[0].vc
		}
		result.Candidates = append(result.Candidates, Candidate{
			InputDescriptor: *descriptor,
			VC:              selected,
		})
	}

	// Step 3: enforce the submission-requirement rules. Candidates is returned even on error so
	// callers can diagnose the assignment that failed.
	if len(pd.SubmissionRequirements) == 0 {
		// With no submission requirements every descriptor is required.
		if err := requireAllFilled(result.Candidates); err != nil {
			return result, err
		}
	} else {
		applied, err := applySubmissionRequirements(pd, result.Candidates)
		if err != nil {
			return result, err
		}
		result.Candidates = applied
	}

	return result, nil
}

// applySubmissionRequirements enforces the submission-requirement rules over the chosen assignment
// and returns it with rule-excluded descriptors cleared (VC=nil).
func applySubmissionRequirements(pd PresentationDefinition, candidates []Candidate) ([]Candidate, error) {
	// Every group referenced by an input descriptor must be covered by a submission requirement.
	availableGroups := make(map[string]groupCandidates)
	for _, submissionRequirement := range pd.SubmissionRequirements {
		for _, group := range submissionRequirement.groups() {
			availableGroups[group] = groupCandidates{Name: group}
		}
	}
	for _, group := range pd.groups() {
		if _, ok := availableGroups[group.Name]; !ok {
			return nil, fmt.Errorf("group '%s' is required but not available", group.Name)
		}
	}
	for _, candidate := range candidates {
		for _, group := range candidate.InputDescriptor.Group {
			current := availableGroups[group]
			current.Candidates = append(current.Candidates, candidate)
			availableGroups[group] = current
		}
	}

	var selectedVCs []vc.VerifiableCredential
	for _, submissionRequirement := range pd.SubmissionRequirements {
		vcs, err := submissionRequirement.match(availableGroups)
		if err != nil {
			return nil, err
		}
		selectedVCs = append(selectedVCs, vcs...)
	}
	selectedVCs = deduplicate(selectedVCs)

	// Clear the descriptors whose chosen VC a rule excluded.
	result := make([]Candidate, len(candidates))
	for i, candidate := range candidates {
		result[i] = candidate
		if candidate.VC == nil || !containsVC(selectedVCs, *candidate.VC) {
			result[i].VC = nil
		}
	}
	return result, nil
}

// containsVC reports whether target is present in vcs, compared by value.
func containsVC(vcs []vc.VerifiableCredential, target vc.VerifiableCredential) bool {
	for _, candidate := range vcs {
		if vcEqual(candidate, target) {
			return true
		}
	}
	return false
}

// requireAllFilled reports ErrNoCredentials when any descriptor was left unfilled. It encodes the
// rule that, with no submission requirements, every descriptor is mandatory.
func requireAllFilled(candidates []Candidate) error {
	var unmatched []string
	for _, candidate := range candidates {
		if candidate.VC == nil {
			unmatched = append(unmatched, fmt.Sprintf("no VC for InputDescriptor (%s)", candidate.InputDescriptor.Id))
		}
	}
	if len(unmatched) > 0 {
		return errors.Join(ErrNoCredentials, fmt.Errorf("constraints not matched: %s", strings.Join(unmatched, ", ")))
	}
	return nil
}

// eligibleCandidate is a credential that passed a descriptor on its own (step 1), paired with the
// field-id -> value bindings it resolves. The bindings drive cross-descriptor consistency.
type eligibleCandidate struct {
	vc       vc.VerifiableCredential
	idValues map[string]string
}

// eligibleCandidates returns the credentials that satisfy a single input descriptor on its own:
// its constraints (matchConstraint) and both the PD-level and descriptor-level format gates. This
// is step 1, evaluated independently of any cross-descriptor binding. The matched id-bearing field
// values are recorded (stringified) for later consistency checks.
func eligibleCandidates(pd PresentationDefinition, descriptor InputDescriptor, candidates []vc.VerifiableCredential) ([]eligibleCandidate, error) {
	var eligible []eligibleCandidate
	for _, candidate := range candidates {
		var idValues map[string]string
		if descriptor.Constraints != nil {
			isMatch, values, err := matchConstraint(descriptor.Constraints, candidate)
			if err != nil {
				return nil, err
			}
			if !isMatch {
				continue
			}
			idValues = make(map[string]string)
			for id, value := range values {
				if s, ok := stringifyBindingValue(value); ok {
					idValues[id] = s
				}
			}
		}
		// InputDescriptor formats must be a subset of the PresentationDefinition formats, so satisfy both.
		if !matchFormat(pd.Format, candidate) || !matchFormat(descriptor.Format, candidate) {
			continue
		}
		eligible = append(eligible, eligibleCandidate{vc: candidate, idValues: idValues})
	}
	return eligible, nil
}

// consistentCandidates keeps the eligible candidates whose resolved id-values agree with the
// running bindings. With no bindings every eligible candidate is consistent.
func consistentCandidates(eligible []eligibleCandidate, bindings map[string]string) []eligibleCandidate {
	if len(bindings) == 0 {
		return eligible
	}
	var consistent []eligibleCandidate
	for _, candidate := range eligible {
		if candidate.consistentWith(bindings) {
			consistent = append(consistent, candidate)
		}
	}
	return consistent
}

// consistentWith reports whether the candidate agrees with the bindings on every shared id. A
// binding key the candidate does not resolve is irrelevant, so a stray key has no effect.
func (c eligibleCandidate) consistentWith(bindings map[string]string) bool {
	for id, value := range c.idValues {
		if bound, ok := bindings[id]; ok && bound != value {
			return false
		}
	}
	return true
}

// isCallerBound reports whether the caller pinned this descriptor by binding one of its field ids.
// Such a descriptor must resolve to a single credential, mirroring the legacy field selector.
func isCallerBound(descriptor InputDescriptor, bindings map[string]string) bool {
	if descriptor.Constraints == nil {
		return false
	}
	for _, field := range descriptor.Constraints.Fields {
		if field.Id == nil {
			continue
		}
		if _, ok := bindings[*field.Id]; ok {
			return true
		}
	}
	return false
}

// stringifyBindingValue renders a resolved field value as the string used for binding comparison:
// strings as-is, float64 without a trailing zero exponent, bool as true/false. Any other type
// (including nil, e.g. an unresolved optional field) is not bindable.
func stringifyBindingValue(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}
