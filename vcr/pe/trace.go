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
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/sirupsen/logrus"
)

// matchSink receives diagnostic events from the matching algorithm. The matching code calls
// it unconditionally, so the algorithm itself stays free of debug-vs-production branching.
//
// noopSink is used when debug logging is off; traceSink builds a matchTrace and emits it on
// emit(). The constructor newSink picks the right one based on the current log level.
type matchSink interface {
	// inputDescriptor marks the start of evaluating an InputDescriptor against `considered`
	// candidate credentials. Pointer arguments are used so the no-op implementation pays
	// no copy cost on the production hot path.
	inputDescriptor(inputDescriptor *InputDescriptor, considered int)
	// rejected records that one credential was rejected by the current InputDescriptor and
	// why. The sink decides whether to compute the (expensive) reason; production no-op
	// implementations can ignore the call entirely.
	rejected(inputDescriptor *InputDescriptor, pdFormat *PresentationDefinitionClaimFormatDesignations, credential *vc.VerifiableCredential, isMatch, formatOK bool)
	// selected closes the current InputDescriptor with the final selection. `selected` is
	// nil when no credential matched.
	selected(matched int, selected *vc.VerifiableCredential)
	// submissionRequirement records the outcome of one SubmissionRequirement. matchErr is
	// nil when the requirement was satisfied.
	submissionRequirement(sr *SubmissionRequirement, availableGroups map[string]groupCandidates, matchErr error)
	// emit is called once after matching completes. `satisfied` reports whether the
	// PresentationDefinition matched (i.e. Match would not have returned an error). Real
	// sinks render and write the trace here; the noop sink does nothing.
	emit(satisfied bool)
}

// newSink returns the sink that the current log level wants. Always emits a noopSink when
// debug logging is off so the matching algorithm pays no diagnostic cost in production.
func newSink() matchSink {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		return &traceSink{trace: matchTrace{}}
	}
	return noopSink{}
}

// noopSink discards every diagnostic event.
type noopSink struct{}

func (noopSink) inputDescriptor(*InputDescriptor, int) {}
func (noopSink) rejected(*InputDescriptor, *PresentationDefinitionClaimFormatDesignations, *vc.VerifiableCredential, bool, bool) {
}
func (noopSink) selected(int, *vc.VerifiableCredential)                                          {}
func (noopSink) submissionRequirement(*SubmissionRequirement, map[string]groupCandidates, error) {}
func (noopSink) emit(bool)                                                                       {}

// traceSink accumulates a matchTrace and emits it as a debug log line on emit().
type traceSink struct {
	trace matchTrace
	cur   *inputDescriptorTrace
}

func (s *traceSink) inputDescriptor(inputDescriptor *InputDescriptor, considered int) {
	s.cur = &inputDescriptorTrace{Id: inputDescriptor.Id, Considered: considered}
}

func (s *traceSink) rejected(inputDescriptor *InputDescriptor, pdFormat *PresentationDefinitionClaimFormatDesignations, credential *vc.VerifiableCredential, isMatch, formatOK bool) {
	// Format failures and "no constraints" rejections are always traced.
	if !formatOK {
		s.cur.Rejections = append(s.cur.Rejections, rejectionTrace{
			Credential: credentialID(credential),
			Reason:     formatRejectionReason(pdFormat, inputDescriptor.Format, credential),
		})
		return
	}
	if inputDescriptor.Constraints == nil {
		s.cur.Rejections = append(s.cur.Rejections, rejectionTrace{
			Credential: credentialID(credential),
			Reason:     "credential rejected",
		})
		return
	}
	credentialAsMap, err := credentialToMap(credential)
	if err != nil {
		s.cur.Rejections = append(s.cur.Rejections, rejectionTrace{
			Credential: credentialID(credential),
			Reason:     "could not parse credential: " + err.Error(),
		})
		return
	}
	// Walk the constraint to find the field that actually rejected this credential.
	// If it was the `$.type` field, suppress the per-credential rejection line: type
	// rejections are common, very noisy and almost never the bug being debugged.
	field, reason := firstFailingField(inputDescriptor.Constraints, credentialAsMap)
	if field != nil && isTypeField(*field) {
		if s.cur.TypeFilter == "" {
			s.cur.TypeFilter = describeTypeFilter(*field)
		}
		return
	}
	s.cur.Rejections = append(s.cur.Rejections, rejectionTrace{
		Credential: credentialID(credential),
		Reason:     reason,
	})
}

// firstFailingField returns the first field in the constraint that rejects the credential,
// together with a human-readable reason. Returns (nil, "") if the constraint actually matches
// (which would indicate a bug in the caller).
func firstFailingField(constraint *Constraints, credentialAsMap map[string]interface{}) (*Field, string) {
	for i := range constraint.Fields {
		field := &constraint.Fields[i]
		if reason := explainFieldMismatch(*field, credentialAsMap); reason != "" {
			return field, reason
		}
	}
	return nil, ""
}

// isTypeField reports whether a constraint field filters on the credential's `$.type` field.
func isTypeField(field Field) bool {
	for _, p := range field.Path {
		if p == "$.type" {
			return true
		}
	}
	return false
}

// describeTypeFilter renders the expected-type description used in the
// "no credentials matched the type X" summary line.
func describeTypeFilter(field Field) string {
	if field.Filter == nil {
		return "(any)"
	}
	if field.Filter.Const != nil {
		return *field.Filter.Const
	}
	if len(field.Filter.Enum) > 0 {
		return fmt.Sprintf("in %v", field.Filter.Enum)
	}
	if field.Filter.Pattern != nil {
		return fmt.Sprintf("matching %s", *field.Filter.Pattern)
	}
	return "(unspecified)"
}

func (s *traceSink) selected(matched int, selected *vc.VerifiableCredential) {
	s.cur.Matched = matched
	if selected != nil {
		s.cur.Selected = credentialID(selected)
	}
	s.trace.InputDescriptors = append(s.trace.InputDescriptors, *s.cur)
	s.cur = nil
}

func (s *traceSink) submissionRequirement(sr *SubmissionRequirement, availableGroups map[string]groupCandidates, matchErr error) {
	s.trace.SubmissionRequirements = append(s.trace.SubmissionRequirements, buildSubmissionRequirementTrace(sr, availableGroups, matchErr))
}

func (s *traceSink) emit(satisfied bool) {
	s.trace.Satisfied = satisfied
	log.Logger().Debug(s.trace.String())
}

// matchTrace summarises how a PresentationDefinition matched the input credentials. It is
// emitted as a multi-line debug log message so that a developer reading the log can quickly
// see, per InputDescriptor, which credentials were considered, which one was selected, and
// the reason any rejected credential failed. When the PresentationDefinition uses submission
// requirements, the per-requirement outcomes are appended too.
type matchTrace struct {
	// Satisfied is the overall outcome — true when the PresentationDefinition matched (i.e.
	// Match would not have returned an error).
	Satisfied              bool
	InputDescriptors       []inputDescriptorTrace
	SubmissionRequirements []submissionRequirementTrace
}

// inputDescriptorTrace summarises how one InputDescriptor evaluated against the input credentials.
type inputDescriptorTrace struct {
	// Id is the InputDescriptor's id, as defined in the PresentationDefinition.
	Id string
	// Considered is the number of credentials that were evaluated against this InputDescriptor.
	Considered int
	// Matched is the number of credentials that satisfied both the format check and the constraints.
	Matched int
	// Selected is the id of the credential the selector picked for this InputDescriptor.
	// Empty when no credential matched.
	Selected string
	// Rejections lists every credential that was evaluated and rejected for a non-type
	// reason. Type-only rejections (the credential's `$.type` failing the descriptor's type
	// filter) are intentionally not listed individually — they're noisy and unsurprising —
	// and are summarised via TypeFilter when no other reasons remain.
	Rejections []rejectionTrace
	// TypeFilter is set when one or more credentials were rejected because the descriptor's
	// `$.type` filter rejected them. Holds a short description of the expected type
	// ("HealthcareOrganizationCredential", `matching ^Foo`, etc.). Rendered as a single
	// "no credentials matched the type X" line when matched == 0 and Rejections is empty.
	TypeFilter string
}

// rejectionTrace describes a single credential that was rejected by an InputDescriptor.
type rejectionTrace struct {
	// Credential is the rejected credential's id, as a string.
	// Empty for self-attested credentials that have no id.
	Credential string
	// Reason is a human-readable explanation of which constraint or format check rejected the
	// credential — typically naming the failing field, JSON path, found value, and expected filter.
	Reason string
}

// submissionRequirementTrace summarises how one SubmissionRequirement evaluated.
type submissionRequirementTrace struct {
	// Name is the SubmissionRequirement's human-readable name, if set.
	Name string
	// Rule is the rule applied to the group ("all" or "pick").
	Rule string
	// From is the group name this requirement draws from. Empty if FromNested is used.
	From string
	// FromNested is the number of nested requirements when "from_nested" is used. Zero if From is set.
	FromNested int
	// Min, Max, Count are the optional bounds copied from the SubmissionRequirement.
	Min   *int
	Max   *int
	Count *int
	// Available is the number of input descriptors in the source group(s) that produced a
	// matching credential. Used to explain why min/count failed. Rendered as `available=<n>`
	// in the human-readable trace.
	Available int
	// Satisfied is true when the SubmissionRequirement was met.
	Satisfied bool
	// Reason explains why a SubmissionRequirement was not satisfied. Empty when Satisfied is true.
	Reason string
}

// String renders the trace in a human-friendly multi-line form for debug log output.
// Format:
//
//	PE: match evaluated (satisfied|not satisfied)
//	  input descriptor "<id>" considered=<n> matched=<n> selected=<id-or-none>
//	    rejected <credential-id-or-(no id)>: <reason>
//	    ...
//	  submission requirement ["<name>"] rule=<rule> [from=<group>|from_nested=<n>] [min=<n>] [max=<n>] [count=<n>] available=<n>: <satisfied|not satisfied: reason>
//	    ...
func (t matchTrace) String() string {
	var b strings.Builder
	b.WriteString("PE: match evaluated (")
	if t.Satisfied {
		b.WriteString("satisfied")
	} else {
		b.WriteString("not satisfied")
	}
	b.WriteString(")")
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
		// If matched==0 and the only failures were credentials with the wrong type, emit a
		// single line instead of one rejection per credential — that's the common case and
		// listing each one is noise.
		if d.Matched == 0 && len(d.Rejections) == 0 && d.TypeFilter != "" {
			fmt.Fprintf(&b, "\n    no credentials matched the type %s", d.TypeFilter)
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
		fmt.Fprintf(&b, " available=%d", sr.Available)
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
func buildSubmissionRequirementTrace(sr *SubmissionRequirement, availableGroups map[string]groupCandidates, matchErr error) submissionRequirementTrace {
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
				t.Available++
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
func rejectionReason(pdFormat *PresentationDefinitionClaimFormatDesignations, inputDescriptor *InputDescriptor, credential *vc.VerifiableCredential, constraintsMatched, formatOK bool) string {
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
func formatRejectionReason(pdFormat, idFormat *PresentationDefinitionClaimFormatDesignations, credential *vc.VerifiableCredential) string {
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
func describeCredentialFormat(credential *vc.VerifiableCredential) string {
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
func describeFormatMismatch(source string, format *PresentationDefinitionClaimFormatDesignations, credential *vc.VerifiableCredential) string {
	if format == nil || len(*format) == 0 {
		return ""
	}
	if matchFormat(format, *credential) {
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
		return fmt.Sprintf("%s requires %s alg in %v", source, credFormat, formatEntry[jws.AlgorithmKey])
	case vc.JSONLDCredentialProofFormat:
		return fmt.Sprintf("%s requires %s proof_type in %v", source, credFormat, formatEntry["proof_type"])
	}
	// matchFormat only inspects ldp_vc and jwt_vc, so credFormat is guaranteed to be one of
	// the cases above. Return empty rather than carry a fallback message that can never fire.
	return ""
}

// credentialID returns the credential's id as a string, or "" if the credential has no id.
func credentialID(credential *vc.VerifiableCredential) string {
	if credential == nil || credential.ID == nil {
		return ""
	}
	return credential.ID.String()
}

// credentialToMap unmarshals a credential to a generic map, regardless of its on-the-wire format.
// Mirrors the conversion done in matchConstraint.
func credentialToMap(credential *vc.VerifiableCredential) (map[string]interface{}, error) {
	switch credential.Format() {
	case vc.JWTCredentialProofFormat:
		type Alias vc.VerifiableCredential
		return remarshalToMap(Alias(*credential))
	default:
		return remarshalToMap(*credential)
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
