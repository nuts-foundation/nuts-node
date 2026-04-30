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
	"encoding/json"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
)

// MatchReport is a developer-facing diagnostic of how a PresentationDefinition matched
// against a set of credentials. It is produced by [PresentationDefinition.Explain].
//
// MatchReport is intended for development and debugging — it does extra work compared to
// the production [PresentationDefinition.Match] path so that humans can see, per input
// descriptor and per credential, why a credential was accepted or rejected.
type MatchReport struct {
	// Satisfied is true when the PresentationDefinition would successfully select credentials
	// from the given input set. Equivalent to "Match would not have returned ErrNoCredentials".
	Satisfied bool `json:"satisfied"`
	// InputDescriptors contains one entry per InputDescriptor in the PresentationDefinition.
	InputDescriptors []InputDescriptorReport `json:"input_descriptors"`
	// SubmissionRequirements contains one entry per SubmissionRequirement, if the
	// PresentationDefinition uses them. Empty otherwise.
	SubmissionRequirements []SubmissionRequirementReport `json:"submission_requirements,omitempty"`
}

// InputDescriptorReport describes how one InputDescriptor evaluated against the input credentials.
type InputDescriptorReport struct {
	Id   string `json:"id"`
	Name string `json:"name,omitempty"`
	// SelectedCredentialId is the id of the credential picked for this input descriptor.
	// Empty when no credential matched.
	SelectedCredentialId string `json:"selected_credential_id,omitempty"`
	// Considered lists every credential that was evaluated against this input descriptor,
	// matched or not.
	Considered []ConsideredCredentialReport `json:"considered"`
}

// ConsideredCredentialReport describes the outcome of evaluating one credential against
// one input descriptor.
type ConsideredCredentialReport struct {
	// CredentialId is the id of the credential. Empty for self-attested credentials with no id.
	CredentialId string `json:"credential_id,omitempty"`
	// Matched is true when the credential satisfied both the format and the constraints of the
	// input descriptor.
	Matched bool `json:"matched"`
	// Reason explains why the credential was rejected. Empty when Matched is true.
	Reason string `json:"reason,omitempty"`
}

// SubmissionRequirementReport describes how one SubmissionRequirement evaluated.
type SubmissionRequirementReport struct {
	Name string `json:"name,omitempty"`
	Rule string `json:"rule"`
	From string `json:"from,omitempty"`
	Min  *int   `json:"min,omitempty"`
	Max  *int   `json:"max,omitempty"`
	// Satisfied is true when the requirement was satisfied by the available credentials.
	Satisfied bool `json:"satisfied"`
	// Reason explains why the requirement was not satisfied. Empty when Satisfied is true.
	Reason string `json:"reason,omitempty"`
}

// Explain produces a [MatchReport] for the given credentials, describing how each
// InputDescriptor matched and why each non-matching credential was rejected. It does
// strictly more work than [PresentationDefinition.Match] and is intended for development
// and debugging — not for the request hot path.
func (presentationDefinition PresentationDefinition) Explain(vcs []vc.VerifiableCredential) (MatchReport, error) {
	report := MatchReport{
		InputDescriptors: make([]InputDescriptorReport, 0, len(presentationDefinition.InputDescriptors)),
	}

	for _, inputDescriptor := range presentationDefinition.InputDescriptors {
		descReport := InputDescriptorReport{
			Id:         inputDescriptor.Id,
			Name:       inputDescriptor.Name,
			Considered: make([]ConsideredCredentialReport, 0, len(vcs)),
		}
		var matched []vc.VerifiableCredential
		for _, credential := range vcs {
			entry := ConsideredCredentialReport{CredentialId: credentialID(credential)}
			formatOK := matchFormat(presentationDefinition.Format, credential) && matchFormat(inputDescriptor.Format, credential)
			if !formatOK {
				entry.Reason = "credential format/proof_type does not satisfy presentation definition or input descriptor format"
				descReport.Considered = append(descReport.Considered, entry)
				continue
			}
			isMatch, err := matchCredential(*inputDescriptor, credential)
			if err != nil {
				return MatchReport{}, fmt.Errorf("input descriptor %q credential %q: %w", inputDescriptor.Id, entry.CredentialId, err)
			}
			if isMatch {
				entry.Matched = true
				descReport.Considered = append(descReport.Considered, entry)
				matched = append(matched, credential)
				continue
			}
			// Re-evaluate to produce a human-readable rejection reason.
			credentialAsMap, mapErr := credentialToMap(credential)
			if mapErr != nil {
				entry.Reason = fmt.Sprintf("could not parse credential: %s", mapErr.Error())
			} else if inputDescriptor.Constraints == nil {
				entry.Reason = "credential rejected (no constraints on input descriptor — this is a bug)"
			} else {
				entry.Reason = explainConstraintMismatch(inputDescriptor.Constraints, credentialAsMap)
			}
			descReport.Considered = append(descReport.Considered, entry)
		}
		if len(matched) > 0 {
			descReport.SelectedCredentialId = credentialID(matched[0])
		}
		report.InputDescriptors = append(report.InputDescriptors, descReport)
	}

	// Determine overall satisfaction by running the production matcher.
	// Match returns ErrNoCredentials (wrapped) when something doesn't match.
	_, _, err := presentationDefinition.Match(vcs)
	report.Satisfied = err == nil

	// Submission requirements (best-effort summary).
	if len(presentationDefinition.SubmissionRequirements) > 0 {
		report.SubmissionRequirements = explainSubmissionRequirements(presentationDefinition, vcs)
	}

	return report, nil
}

// credentialID returns the credential's id as a string, or "" if the credential has no id.
func credentialID(credential vc.VerifiableCredential) string {
	if credential.ID == nil {
		return ""
	}
	return credential.ID.String()
}

// credentialToMap unmarshals a credential to a generic map, regardless of its on-the-wire format.
// Mirrors the conversion done in matchConstraint.
func credentialToMap(credential vc.VerifiableCredential) (map[string]interface{}, error) {
	switch credential.Format() {
	case vc.JWTCredentialProofFormat:
		type Alias vc.VerifiableCredential
		return remarshalToMap(Alias(credential))
	default:
		return remarshalToMap(credential)
	}
}

// explainConstraintMismatch returns a human-readable reason why the given constraint does
// not match the given credential. It assumes the constraint has already been determined
// not to match. Returns a generic message if no individual field rejects (which would be a bug).
func explainConstraintMismatch(constraint *Constraints, credentialAsMap map[string]interface{}) string {
	for _, field := range constraint.Fields {
		if reason := explainFieldMismatch(field, credentialAsMap); reason != "" {
			return reason
		}
	}
	return "no individual field rejected the credential"
}

// explainFieldMismatch returns a human-readable reason why the given field does not match
// the credential, or "" if the field does match.
func explainFieldMismatch(field Field, credential map[string]interface{}) string {
	var lastFoundPath string
	var lastFoundValue interface{}
	var optionalInvalid int
	for _, path := range field.Path {
		value, err := getValueAtPath(path, credential)
		if err != nil {
			return fmt.Sprintf("%spath %q: %s", fieldLabel(field), path, err.Error())
		}
		if value == nil {
			continue
		}
		if field.Filter == nil {
			return ""
		}
		match, _, err := matchFilter(*field.Filter, value)
		if err != nil {
			return fmt.Sprintf("%spath %q value %v: %s", fieldLabel(field), path, value, err.Error())
		}
		if match {
			return ""
		}
		lastFoundPath = path
		lastFoundValue = value
		optionalInvalid++
	}
	if field.Optional != nil && *field.Optional && optionalInvalid == 0 {
		return ""
	}
	if optionalInvalid > 0 {
		filterDesc, _ := json.Marshal(field.Filter)
		return fmt.Sprintf("%spath %q found value %v which did not match filter %s", fieldLabel(field), lastFoundPath, lastFoundValue, filterDesc)
	}
	return fmt.Sprintf("%sno value found at any of paths %v", fieldLabel(field), field.Path)
}

func fieldLabel(field Field) string {
	if field.Id != nil {
		return fmt.Sprintf("field %q ", *field.Id)
	}
	return ""
}

// explainSubmissionRequirements returns a summary of how each SubmissionRequirement evaluated.
// It is best-effort: it reports min/max/from/rule plus whether the requirement was satisfied,
// without re-implementing the full submission requirement algorithm.
func explainSubmissionRequirements(pd PresentationDefinition, vcs []vc.VerifiableCredential) []SubmissionRequirementReport {
	candidates, err := pd.matchConstraints(vcs, FirstMatchSelector)
	if err != nil {
		// Production matcher would surface this; here we just return an empty list.
		return nil
	}
	availableGroups := make(map[string]groupCandidates)
	for _, sr := range pd.SubmissionRequirements {
		for _, group := range sr.groups() {
			availableGroups[group] = groupCandidates{Name: group}
		}
	}
	for _, c := range candidates {
		for _, group := range c.InputDescriptor.Group {
			cur := availableGroups[group]
			cur.Candidates = append(cur.Candidates, c)
			availableGroups[group] = cur
		}
	}
	reports := make([]SubmissionRequirementReport, 0, len(pd.SubmissionRequirements))
	for _, sr := range pd.SubmissionRequirements {
		r := SubmissionRequirementReport{
			Name: sr.Name,
			Rule: sr.Rule,
			From: sr.From,
			Min:  sr.Min,
			Max:  sr.Max,
		}
		_, err := sr.match(availableGroups)
		if err != nil {
			r.Reason = err.Error()
		} else {
			r.Satisfied = true
		}
		reports = append(reports, r)
	}
	return reports
}
