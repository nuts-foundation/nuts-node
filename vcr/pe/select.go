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
	"strings"

	"github.com/nuts-foundation/go-did/vc"
)

// selectOptions holds the knobs configured by the Option functions passed to Select.
type selectOptions struct {
}

// Option configures a single Select call. Options exist so that callers can opt in to
// behaviour (initial bindings, strict ambiguity detection, tracing) without widening the
// Select signature for every new knob.
type Option func(*selectOptions)

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
	var result Result
	for _, descriptor := range pd.InputDescriptors {
		eligible, err := eligibleCandidates(pd, *descriptor, candidates)
		if err != nil {
			return Result{}, err
		}
		var selected *vc.VerifiableCredential
		if len(eligible) > 0 {
			selected = &eligible[0]
		}
		result.Candidates = append(result.Candidates, Candidate{
			InputDescriptor: *descriptor,
			VC:              selected,
		})
	}

	if len(pd.SubmissionRequirements) == 0 {
		// With no submission requirements every descriptor is required.
		// Candidates is returned even on error so callers can diagnose the unfilled descriptors.
		if err := requireAllFilled(result.Candidates); err != nil {
			return result, err
		}
	}

	return result, nil
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

// eligibleCandidates returns the credentials that satisfy a single input descriptor on its own:
// its constraints (matchConstraint) and both the PD-level and descriptor-level format gates. This
// is step 1, evaluated independently of any cross-descriptor binding.
func eligibleCandidates(pd PresentationDefinition, descriptor InputDescriptor, candidates []vc.VerifiableCredential) ([]vc.VerifiableCredential, error) {
	var eligible []vc.VerifiableCredential
	for _, candidate := range candidates {
		isMatch, err := matchCredential(descriptor, candidate)
		if err != nil {
			return nil, err
		}
		// InputDescriptor formats must be a subset of the PresentationDefinition formats, so satisfy both.
		if isMatch && matchFormat(pd.Format, candidate) && matchFormat(descriptor.Format, candidate) {
			eligible = append(eligible, candidate)
		}
	}
	return eligible, nil
}
