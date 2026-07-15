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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
)

// Outcome classifies the overall result of a Select call in a MatchReport.
type Outcome string

const (
	// OutcomeMatched means a complete, binding-consistent assignment was found.
	OutcomeMatched Outcome = "matched"
	// OutcomeNoCredentials means some required descriptor could not be filled consistently.
	OutcomeNoCredentials Outcome = "no_credentials"
	// OutcomeMultipleCredentials means the selection was ambiguous.
	OutcomeMultipleCredentials Outcome = "multiple_credentials"
)

// DismissalReason classifies why a candidate credential was not used for a descriptor.
type DismissalReason string

const (
	// ReasonNoValue means no path of a required field produced a value.
	ReasonNoValue DismissalReason = "constraint_no_value"
	// ReasonFilter means a field resolved a value that its filter rejected.
	ReasonFilter DismissalReason = "constraint_filter"
	// ReasonFormat means the credential format did not satisfy the PD or descriptor format gate.
	ReasonFormat DismissalReason = "format_mismatch"
	// ReasonBindingConflict means the credential was eligible but disagrees with the decisive
	// assignment on a shared field id.
	ReasonBindingConflict DismissalReason = "binding_conflict"
	// ReasonNotSelected means the credential was eligible and consistent, but another candidate
	// was chosen.
	ReasonNotSelected DismissalReason = "not_selected"
)

// MatchReport explains, per input descriptor, why each candidate credential was or wasn't
// selected. It is produced only under WithSelectionTrace.
type MatchReport struct {
	// Descriptors reports on every input descriptor, in PD order.
	Descriptors []DescriptorReport
	// Outcome classifies the overall result.
	Outcome Outcome
	// AmbiguousDescriptors names the descriptors that carried more than one choice
	// (OutcomeMultipleCredentials only).
	AmbiguousDescriptors []string
}

// DescriptorReport explains the selection for one input descriptor.
type DescriptorReport struct {
	DescriptorID string
	// Optional is whether the search was allowed to leave the descriptor unfilled.
	Optional bool
	// Considered reports every candidate credential evaluated against this descriptor.
	Considered []CandidateReport
	// SelectedID is the id of the chosen credential, empty when the descriptor went unfilled.
	SelectedID string
	// Skipped is whether the descriptor ended up without a credential.
	Skipped bool
	// DivergingAlternatives is whether the chosen credential was picked among interchangeable
	// alternatives (agreeing on every declared field id) whose credentialSubjects nevertheless
	// differ. The PD does not declare the differing fields, so they played no role in selection;
	// this flag gives the operator visibility into a wallet holding such diverging credentials.
	DivergingAlternatives bool
}

// CandidateReport explains one credential's evaluation against one descriptor.
type CandidateReport struct {
	CredentialID string
	// Eligible is whether the credential passed the descriptor's constraints and format gates.
	Eligible bool
	// Dismissal explains why the credential was not used; nil for the selected credential.
	Dismissal *Dismissal
}

// Dismissal is the reason a candidate was not used, with the offending field where known.
type Dismissal struct {
	Reason DismissalReason
	// FieldID is the field id involved (constraint and binding reasons, when known).
	FieldID string
	// Path is the JSONPath that was evaluated (constraint reasons).
	Path string
	// Expected is the filter constant or type, or the bound value (binding conflicts).
	Expected string
	// Found is the value the credential resolved; empty when none.
	Found string
	// Message is a rendered human-readable line.
	Message string
}

// buildReport assembles the MatchReport after a Select run. It re-evaluates step 1 per descriptor
// and candidate to recover the dismissal reasons, so a non-traced run pays nothing. Binding
// conflicts are explained against the decisive assignment (the chosen one, or the best-effort
// diagnostic assignment on failure), not against every backtracking visit.
func buildReport(pd PresentationDefinition, candidates []vc.VerifiableCredential, required []bool,
	assignment []*candidateGroup, ambiguous []string, result Result, err error, initialBindings map[string]string) *MatchReport {
	report := &MatchReport{
		Outcome:              OutcomeMatched,
		AmbiguousDescriptors: ambiguous,
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrMultipleCredentials):
		report.Outcome = OutcomeMultipleCredentials
	default:
		report.Outcome = OutcomeNoCredentials
	}

	// the decisive bindings: the caller's plus everything the decisive assignment resolved
	bindings := copyBindings(initialBindings)
	for _, group := range assignment {
		if group == nil {
			continue
		}
		for id, value := range group.idValues {
			if _, bound := bindings[id]; !bound {
				bindings[id] = value
			}
		}
	}

	for i, descriptor := range pd.InputDescriptors {
		descriptorReport := DescriptorReport{
			DescriptorID: descriptor.Id,
			Optional:     i < len(required) && !required[i],
		}
		selected := result.Candidates[i].VC
		if selected != nil && selected.ID != nil {
			descriptorReport.SelectedID = selected.ID.String()
		}
		descriptorReport.Skipped = selected == nil
		strictIDs := strictBoundIDs(*descriptor, initialBindings)

		var selectedIDValues map[string]string
		if selected != nil {
			_, selectedIDValues = evaluateCandidate(pd, *descriptor, *selected)
		}
		selectedSeen := false
		for _, candidate := range candidates {
			candidateReport := CandidateReport{}
			if candidate.ID != nil {
				candidateReport.CredentialID = candidate.ID.String()
			}
			eligible, idValues := evaluateCandidate(pd, *descriptor, candidate)
			candidateReport.Eligible = eligible
			switch {
			case !eligible:
				candidateReport.Dismissal = explainIneligible(pd, *descriptor, candidate)
			case selected != nil && !selectedSeen && vcEqual(candidate, *selected):
				selectedSeen = true // the chosen credential carries no dismissal
			default:
				candidateReport.Dismissal = explainNotChosen(idValues, bindings, strictIDs)
				// An interchangeable alternative (same binding tuple as the chosen credential)
				// whose subject nevertheless differs is worth the operator's attention.
				if selected != nil && tupleKey(idValues) == tupleKey(selectedIDValues) && !subjectsEqual(candidate, *selected) {
					descriptorReport.DivergingAlternatives = true
				}
			}
			descriptorReport.Considered = append(descriptorReport.Considered, candidateReport)
		}
		report.Descriptors = append(report.Descriptors, descriptorReport)
	}
	return report
}

// subjectsEqual reports whether two credentials carry structurally equal credentialSubjects.
// Metadata (proof, VC id, dates) is deliberately not compared.
func subjectsEqual(a, b vc.VerifiableCredential) bool {
	aJSON, errA := json.Marshal(a.CredentialSubject)
	bJSON, errB := json.Marshal(b.CredentialSubject)
	return errA == nil && errB == nil && bytes.Equal(aJSON, bJSON)
}

// evaluateCandidate re-runs the step-1 eligibility of one credential for one descriptor.
func evaluateCandidate(pd PresentationDefinition, descriptor InputDescriptor, credential vc.VerifiableCredential) (bool, map[string]string) {
	idValues := make(map[string]string)
	if descriptor.Constraints != nil {
		isMatch, values, err := matchConstraint(descriptor.Constraints, credential)
		if err != nil || !isMatch {
			return false, nil
		}
		for id, value := range values {
			if s, ok := stringifyBindingValue(value); ok {
				idValues[id] = s
			}
		}
	}
	if !matchFormat(pd.Format, credential) || !matchFormat(descriptor.Format, credential) {
		return false, nil
	}
	return true, idValues
}

// explainIneligible pinpoints why a credential failed step 1: the first failing constraint field
// (filter rejection or missing value), or the format gate.
func explainIneligible(pd PresentationDefinition, descriptor InputDescriptor, credential vc.VerifiableCredential) *Dismissal {
	if descriptor.Constraints != nil {
		credentialJSON, err := credentialAsMap(credential)
		if err != nil {
			return &Dismissal{Reason: ReasonNoValue, Message: err.Error()}
		}
		for _, field := range descriptor.Constraints.Fields {
			if match, _, err := matchField(field, credentialJSON); err == nil && match {
				continue
			}
			return explainFieldMismatch(field, credentialJSON)
		}
	}
	dismissal := &Dismissal{Reason: ReasonFormat}
	dismissal.Message = fmt.Sprintf("credential format does not satisfy the format requirements of the presentation definition or input descriptor '%s'", descriptor.Id)
	return dismissal
}

// explainFieldMismatch distinguishes "a value was found but the filter rejected it" from "no path
// produced a value".
func explainFieldMismatch(field Field, credentialJSON map[string]interface{}) *Dismissal {
	dismissal := &Dismissal{}
	if field.Id != nil {
		dismissal.FieldID = *field.Id
	}
	for _, path := range field.Path {
		value, err := getValueAtPath(path, credentialJSON)
		if err != nil || value == nil {
			continue
		}
		dismissal.Reason = ReasonFilter
		dismissal.Path = path
		dismissal.Found = fmt.Sprintf("%v", value)
		if field.Filter != nil {
			if field.Filter.Const != nil {
				dismissal.Expected = *field.Filter.Const
			} else {
				dismissal.Expected = field.Filter.Type
			}
		}
		dismissal.Message = fmt.Sprintf("value at %s does not satisfy the filter: expected %s, found %s", path, dismissal.Expected, dismissal.Found)
		return dismissal
	}
	dismissal.Reason = ReasonNoValue
	if len(field.Path) > 0 {
		dismissal.Path = field.Path[0]
	}
	dismissal.Message = fmt.Sprintf("no value found at %v", field.Path)
	return dismissal
}

// explainNotChosen explains an eligible credential that was not selected: either it conflicts with
// the decisive bindings on a shared id (or fails to resolve a strictly bound one), or it simply
// lost to an earlier candidate.
func explainNotChosen(idValues map[string]string, bindings map[string]string, strictIDs []string) *Dismissal {
	for id, value := range idValues {
		if bound, ok := bindings[id]; ok && bound != value {
			return &Dismissal{
				Reason:   ReasonBindingConflict,
				FieldID:  id,
				Expected: bound,
				Found:    value,
				Message:  fmt.Sprintf("field id %s resolves to %s, but the selection binds it to %s", id, value, bound),
			}
		}
	}
	for _, id := range strictIDs {
		if _, ok := idValues[id]; !ok {
			return &Dismissal{
				Reason:   ReasonBindingConflict,
				FieldID:  id,
				Expected: bindings[id],
				Message:  fmt.Sprintf("field id %s is bound to %s but does not resolve on this credential", id, bindings[id]),
			}
		}
	}
	return &Dismissal{Reason: ReasonNotSelected, Message: "not selected: another candidate fills this descriptor"}
}
