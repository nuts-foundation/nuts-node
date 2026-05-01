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

// This file contains the debug-only diagnostic that the production matching algorithm in
// presentation_definition.go emits as a single multi-line log line. It records, per
// InputDescriptor and per SubmissionRequirement, what was considered and why anything was
// rejected. None of this code feeds back into the algorithm's decisions — it only describes them.

package pe

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nuts-foundation/go-did/vc"
)

// matchTrace summarises how a PresentationDefinition matched the input credentials. It is
// emitted as a multi-line debug log message so that a developer reading the log can quickly
// see, per InputDescriptor, which credentials were considered, which one was selected, and
// the reason any rejected credential failed. When the PresentationDefinition uses submission
// requirements, the per-requirement outcomes are appended too.
type matchTrace struct {
	InputDescriptors       []inputDescriptorTrace       `json:"input_descriptors"`
	SubmissionRequirements []submissionRequirementTrace `json:"submission_requirements,omitempty"`
}

// inputDescriptorTrace summarises how one InputDescriptor evaluated against the input credentials.
type inputDescriptorTrace struct {
	// Id is the InputDescriptor's id, as defined in the PresentationDefinition.
	Id string `json:"id"`
	// Considered is the number of credentials that were evaluated against this InputDescriptor.
	Considered int `json:"considered"`
	// Matched is the number of credentials that satisfied both the format check and the constraints.
	Matched int `json:"matched"`
	// Selected is the id of the credential the selector picked for this InputDescriptor.
	// Empty when no credential matched.
	Selected string `json:"selected,omitempty"`
	// Rejections lists every credential that was evaluated and rejected, with the reason.
	// Empty when every considered credential matched.
	Rejections []rejectionTrace `json:"rejections,omitempty"`
}

// rejectionTrace describes a single credential that was rejected by an InputDescriptor.
type rejectionTrace struct {
	// Credential is the rejected credential's id, as a string.
	// Empty for self-attested credentials that have no id.
	Credential string `json:"credential,omitempty"`
	// Reason is a human-readable explanation of which constraint or format check rejected the
	// credential — typically naming the failing field, JSON path, found value, and expected filter.
	Reason string `json:"reason"`
}

// submissionRequirementTrace summarises how one SubmissionRequirement evaluated.
type submissionRequirementTrace struct {
	// Name is the SubmissionRequirement's human-readable name, if set.
	Name string `json:"name,omitempty"`
	// Rule is the rule applied to the group ("all" or "pick").
	Rule string `json:"rule"`
	// From is the group name this requirement draws from. Empty if FromNested is used.
	From string `json:"from,omitempty"`
	// FromNested is the number of nested requirements when "from_nested" is used. Zero if From is set.
	FromNested int `json:"from_nested,omitempty"`
	// Min, Max, Count are the optional bounds copied from the SubmissionRequirement.
	Min   *int `json:"min,omitempty"`
	Max   *int `json:"max,omitempty"`
	Count *int `json:"count,omitempty"`
	// AvailableInGroup is the number of input descriptors in the source group that produced
	// a matching credential. Used to explain why min/count failed.
	AvailableInGroup int `json:"available_in_group"`
	// Satisfied is true when the SubmissionRequirement was met.
	Satisfied bool `json:"satisfied"`
	// Reason explains why a SubmissionRequirement was not satisfied. Empty when Satisfied is true.
	Reason string `json:"reason,omitempty"`
}

// String renders the trace in a human-friendly multi-line form for debug log output.
// Format:
//
//	PE: match evaluated
//	  input descriptor "<id>" considered=<n> matched=<n> selected=<id-or-none>
//	    rejected <credential-id-or-(none)>: <reason>
//	    ...
//	  submission requirement "<name>" rule=<rule> from=<group> [min=<n>] [max=<n>] [count=<n>]: <satisfied|not satisfied: reason>
//	    ...
func (t matchTrace) String() string {
	var b strings.Builder
	b.WriteString("PE: match evaluated")
	for _, d := range t.InputDescriptors {
		selected := d.Selected
		if selected == "" {
			selected = "(none)"
		}
		fmt.Fprintf(&b, "\n  input descriptor %q considered=%d matched=%d selected=%s", d.Id, d.Considered, d.Matched, selected)
		for _, r := range d.Rejections {
			cred := r.Credential
			if cred == "" {
				cred = "(no id)"
			}
			fmt.Fprintf(&b, "\n    rejected %s: %s", cred, r.Reason)
		}
	}
	for _, sr := range t.SubmissionRequirements {
		fmt.Fprintf(&b, "\n  submission requirement")
		if sr.Name != "" {
			fmt.Fprintf(&b, " %q", sr.Name)
		}
		fmt.Fprintf(&b, " rule=%s", sr.Rule)
		if sr.From != "" {
			fmt.Fprintf(&b, " from=%s", sr.From)
		}
		if sr.FromNested > 0 {
			fmt.Fprintf(&b, " from_nested=%d", sr.FromNested)
		}
		if sr.Min != nil {
			fmt.Fprintf(&b, " min=%d", *sr.Min)
		}
		if sr.Max != nil {
			fmt.Fprintf(&b, " max=%d", *sr.Max)
		}
		if sr.Count != nil {
			fmt.Fprintf(&b, " count=%d", *sr.Count)
		}
		fmt.Fprintf(&b, " available=%d", sr.AvailableInGroup)
		if sr.Satisfied {
			b.WriteString(": satisfied")
		} else {
			fmt.Fprintf(&b, ": not satisfied: %s", sr.Reason)
		}
	}
	return b.String()
}

// buildSubmissionRequirementTrace produces the trace entry for one SubmissionRequirement
// after evaluating it. matchErr should be the error returned by SubmissionRequirement.match
// (nil if the requirement was satisfied).
func buildSubmissionRequirementTrace(sr SubmissionRequirement, availableGroups map[string]groupCandidates, matchErr error) submissionRequirementTrace {
	t := submissionRequirementTrace{
		Name:       sr.Name,
		Rule:       sr.Rule,
		From:       sr.From,
		FromNested: len(sr.FromNested),
		Min:        sr.Min,
		Max:        sr.Max,
		Count:      sr.Count,
	}
	// Count how many input descriptors in the source group produced a matching credential.
	// For from_nested we sum over the nested 'from' groups.
	groups := sr.groups()
	for _, name := range groups {
		group := availableGroups[name]
		for _, c := range group.Candidates {
			if c.VC != nil {
				t.AvailableInGroup++
			}
		}
	}
	if matchErr != nil {
		// errors.Join uses '\n' as a separator; collapse to ' — ' so the trace stays
		// on logical lines that fit the indentation.
		t.Reason = strings.ReplaceAll(matchErr.Error(), "\n", " — ")
	} else {
		t.Satisfied = true
	}
	return t
}

// rejectionReason produces a human-readable explanation of why a credential was rejected
// by an input descriptor.
func rejectionReason(pdFormat *PresentationDefinitionClaimFormatDesignations, inputDescriptor InputDescriptor, credential vc.VerifiableCredential, constraintsMatched, formatOK bool) string {
	switch {
	case !formatOK:
		return formatRejectionReason(pdFormat, inputDescriptor.Format, credential)
	case !constraintsMatched && inputDescriptor.Constraints != nil:
		credentialAsMap, err := credentialToMap(credential)
		if err != nil {
			return "could not parse credential: " + err.Error()
		}
		return explainConstraintMismatch(inputDescriptor.Constraints, credentialAsMap)
	default:
		return "credential rejected"
	}
}

// formatRejectionReason returns a human-readable explanation of why the credential's format,
// signing algorithm or proof type was rejected. Reports what the credential offered alongside
// what each format spec (presentation definition and/or input descriptor) actually accepts.
func formatRejectionReason(pdFormat, idFormat *PresentationDefinitionClaimFormatDesignations, credential vc.VerifiableCredential) string {
	parts := []string{describeCredentialFormat(credential)}
	if reason := describeFormatMismatch("presentation definition", pdFormat, credential); reason != "" {
		parts = append(parts, reason)
	}
	if reason := describeFormatMismatch("input descriptor", idFormat, credential); reason != "" {
		parts = append(parts, reason)
	}
	return strings.Join(parts, "; ")
}

// describeCredentialFormat returns a short description of the credential's format and the
// cryptographic detail used to sign it (alg for JWT, proof_type for JSON-LD).
func describeCredentialFormat(credential vc.VerifiableCredential) string {
	format := credential.Format()
	switch format {
	case "":
		return "credential is self-attested (no format)"
	case vc.JWTCredentialProofFormat:
		message, err := jws.ParseString(credential.Raw())
		if err != nil || len(message.Signatures()) == 0 {
			return fmt.Sprintf("credential format=%s (could not parse signature)", format)
		}
		alg, _ := message.Signatures()[0].ProtectedHeaders().Get(jws.AlgorithmKey)
		return fmt.Sprintf("credential format=%s alg=%v", format, alg)
	case vc.JSONLDCredentialProofFormat:
		proofs, _ := credential.Proofs()
		if len(proofs) == 0 {
			return fmt.Sprintf("credential format=%s (no proof)", format)
		}
		types := make([]string, 0, len(proofs))
		for _, p := range proofs {
			types = append(types, string(p.Type))
		}
		return fmt.Sprintf("credential format=%s proof_type=%s", format, strings.Join(types, ","))
	default:
		return fmt.Sprintf("credential format=%s", format)
	}
}

// describeFormatMismatch returns a description of why the given format spec rejects the
// credential, or "" if the spec accepts it (or is empty).
func describeFormatMismatch(source string, format *PresentationDefinitionClaimFormatDesignations, credential vc.VerifiableCredential) string {
	if format == nil || len(*format) == 0 {
		return ""
	}
	if matchFormat(format, credential) {
		return ""
	}
	asMap := map[string]map[string][]string(*format)
	credFormat := credential.Format()
	formatEntry, formatAccepted := asMap[credFormat]
	if !formatAccepted {
		accepted := make([]string, 0, len(asMap))
		for f := range asMap {
			accepted = append(accepted, f)
		}
		sort.Strings(accepted)
		return fmt.Sprintf("%s accepts only formats %v", source, accepted)
	}
	switch credFormat {
	case vc.JWTCredentialProofFormat:
		return fmt.Sprintf("%s requires %s alg in %v", source, credFormat, formatEntry[string(jws.AlgorithmKey)])
	case vc.JSONLDCredentialProofFormat:
		return fmt.Sprintf("%s requires %s proof_type in %v", source, credFormat, formatEntry["proof_type"])
	}
	return fmt.Sprintf("%s rejected the credential", source)
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
