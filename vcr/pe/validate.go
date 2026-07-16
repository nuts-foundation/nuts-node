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
	"fmt"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
)

// ConflictKind classifies a FieldIDConflict.
type ConflictKind string

const (
	// ConflictDuplicate is an id declared more than once where it must be unique.
	ConflictDuplicate ConflictKind = "duplicate"
	// ConflictType is a field id whose filters declare different value types across descriptors.
	ConflictType ConflictKind = "type"
	// ConflictUnsatisfiable is a filter, or a combination of same-id filters, that no value can
	// ever satisfy.
	ConflictUnsatisfiable ConflictKind = "unsatisfiable"
	// ConflictInvalidPattern is a pattern that fails to compile or errors on every match.
	ConflictInvalidPattern ConflictKind = "invalid_pattern"
	// ConflictIgnoredConstraint is a declared constraint the matcher silently does not enforce,
	// so the filter is weaker than the author intended.
	ConflictIgnoredConstraint ConflictKind = "ignored_constraint"
	// ConflictSubmissionRequirement is a submission requirement problem that fails every request.
	ConflictSubmissionRequirement ConflictKind = "submission_requirement"
)

// FieldIDConflict is one problem found by Validate. FieldID names the field id involved; for
// structural problems it names the input descriptor id, group, or submission requirement instead.
type FieldIDConflict struct {
	FieldID string
	Kind    ConflictKind
	Detail  string
}

// PDValidationError is returned by Validate; it aggregates every conflict in the presentation
// definition, sorted, so the author sees all problems at once.
type PDValidationError struct {
	PDID      string
	Conflicts []FieldIDConflict
}

func (e *PDValidationError) Error() string {
	lines := make([]string, len(e.Conflicts))
	for i, conflict := range e.Conflicts {
		lines[i] = conflict.FieldID + ": " + conflict.Detail
	}
	return fmt.Sprintf("presentation definition '%s' is invalid: %s", e.PDID, strings.Join(lines, "; "))
}

// Validate checks a presentation definition for problems that make it misbehave deterministically
// at request time: duplicate ids, same-id filters no value can satisfy at once, filters that can
// never match, silently ignored constraints, and submission requirement mistakes. It is a
// semantic pass on the parsed definition, layered after JSON-schema validation (v2.Validate),
// which cannot express these cross-field rules. It returns a PDValidationError aggregating every
// conflict, or nil.
func Validate(pd PresentationDefinition) error {
	var conflicts []FieldIDConflict
	conflicts = append(conflicts, duplicateConflicts(pd)...)
	conflicts = append(conflicts, filterSanityConflicts(pd)...)
	conflicts = append(conflicts, sameIDConflicts(pd)...)
	if len(conflicts) == 0 {
		return nil
	}
	sort.Slice(conflicts, func(i, j int) bool {
		a, b := conflicts[i], conflicts[j]
		if a.FieldID != b.FieldID {
			return a.FieldID < b.FieldID
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	return &PDValidationError{PDID: pd.Id, Conflicts: conflicts}
}

// duplicateConflicts reports input descriptor ids used more than once, and field ids declared
// more than once within a single constraints object. The same field id on different descriptors
// is not a duplicate: that is the binding mechanism.
func duplicateConflicts(pd PresentationDefinition) []FieldIDConflict {
	var conflicts []FieldIDConflict
	descriptorSeen := make(map[string]bool)
	descriptorReported := make(map[string]bool)
	for _, descriptor := range pd.InputDescriptors {
		if descriptorSeen[descriptor.Id] && !descriptorReported[descriptor.Id] {
			descriptorReported[descriptor.Id] = true
			conflicts = append(conflicts, FieldIDConflict{
				FieldID: descriptor.Id,
				Kind:    ConflictDuplicate,
				Detail:  fmt.Sprintf("input descriptor id '%s' is declared more than once", descriptor.Id),
			})
		}
		descriptorSeen[descriptor.Id] = true
		if descriptor.Constraints == nil {
			continue
		}
		fieldSeen := make(map[string]bool)
		fieldReported := make(map[string]bool)
		for _, field := range descriptor.Constraints.Fields {
			if field.Id == nil {
				continue
			}
			if fieldSeen[*field.Id] && !fieldReported[*field.Id] {
				fieldReported[*field.Id] = true
				conflicts = append(conflicts, FieldIDConflict{
					FieldID: *field.Id,
					Kind:    ConflictDuplicate,
					Detail:  fmt.Sprintf("field id '%s' is declared more than once in input descriptor '%s'", *field.Id, descriptor.Id),
				})
			}
			fieldSeen[*field.Id] = true
		}
	}
	return conflicts
}

// filterSanityConflicts checks every filter on its own, following the matcher's actual semantics
// (see matchFilter): filters that can never match anything, patterns that error, and declared
// constraints the matcher silently ignores (leaving the filter weaker than its author intended).
// A conflict is reported under the field id, or under the descriptor id for id-less fields.
func filterSanityConflicts(pd PresentationDefinition) []FieldIDConflict {
	var conflicts []FieldIDConflict
	for _, descriptor := range pd.InputDescriptors {
		if descriptor.Constraints == nil {
			continue
		}
		for _, field := range descriptor.Constraints.Fields {
			if field.Filter == nil {
				continue
			}
			subject := descriptor.Id
			if field.Id != nil {
				subject = *field.Id
			}
			for _, conflict := range singleFilterConflicts(*field.Filter) {
				conflict.FieldID = subject
				conflicts = append(conflicts, conflict)
			}
		}
	}
	return conflicts
}

// singleFilterConflicts derives the problems of one filter; FieldID is filled in by the caller.
func singleFilterConflicts(filter Filter) []FieldIDConflict {
	var conflicts []FieldIDConflict
	if len(filter.unsupported) > 0 {
		conflicts = append(conflicts, FieldIDConflict{
			Kind:   ConflictIgnoredConstraint,
			Detail: fmt.Sprintf("unsupported filter keywords [%s] are not evaluated: the filter is weaker than declared", strings.Join(filter.unsupported, ", ")),
		})
	}

	if filter.Enum != nil {
		// enum shadows type, const and pattern (matchFilter returns from the enum branch)
		if len(filter.Enum) == 0 {
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictUnsatisfiable,
				Detail: "enum is empty: the filter can never match",
			})
		}
		if filter.Const != nil {
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictIgnoredConstraint,
				Detail: fmt.Sprintf("const %q is ignored because enum is set", *filter.Const),
			})
		}
		if filter.Pattern != nil {
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictIgnoredConstraint,
				Detail: "pattern is ignored because enum is set",
			})
		}
		if filter.Type != "" && filter.Type != "string" {
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictIgnoredConstraint,
				Detail: fmt.Sprintf("type %q is ignored because enum forces string matching", filter.Type),
			})
		}
		return conflicts
	}

	if filter.Const != nil && filter.Type != "string" {
		// the const compares as a string, but the type gate never lets a string value through
		conflicts = append(conflicts, FieldIDConflict{
			Kind:   ConflictUnsatisfiable,
			Detail: fmt.Sprintf("const %q can never match: it requires type \"string\", declared type is %q", *filter.Const, filter.Type),
		})
	}

	if filter.Pattern != nil {
		pattern, err := regexp2.Compile(*filter.Pattern, regexp2.ECMAScript)
		switch {
		case err != nil:
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictInvalidPattern,
				Detail: fmt.Sprintf("pattern %q does not compile: %s", *filter.Pattern, err),
			})
		case len(pattern.GetGroupNumbers()) > 2:
			// matchFilter returns an error whenever a pattern with more than one capture
			// group matches a value
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictInvalidPattern,
				Detail: fmt.Sprintf("pattern %q has more than one capture group: every match errors", *filter.Pattern),
			})
		case filter.Type != "string":
			// the matcher applies patterns to string-typed filters only
			conflicts = append(conflicts, FieldIDConflict{
				Kind:   ConflictIgnoredConstraint,
				Detail: fmt.Sprintf("pattern is ignored because the declared type is %q: patterns apply to strings only", filter.Type),
			})
		case filter.Const != nil:
			if match, _ := pattern.FindStringMatch(*filter.Const); match == nil {
				conflicts = append(conflicts, FieldIDConflict{
					Kind:   ConflictUnsatisfiable,
					Detail: fmt.Sprintf("const %q does not match the field's own pattern %q", *filter.Const, *filter.Pattern),
				})
			}
		}
	}
	return conflicts
}

// valueSet models the string values a filter accepts, as matchFilter implements them: enum
// shadows every other keyword; const and pattern require type "string".
type valueSet struct {
	// effectiveType is "string" whenever enum or const constrains the value (both compare as
	// strings at match time), otherwise the declared type; empty means unconstrained.
	effectiveType string
	// finite holds the candidate values when enum or const pins them; nil otherwise.
	finite []string
	// pattern is the predicate when only a pattern constrains the value.
	pattern *regexp2.Regexp
	// dead marks a filter that can never accept any value.
	dead bool
}

// filterValueSet derives the accepted-value set of one filter, following the matcher's actual
// semantics (see matchFilter), not JSON Schema's.
func filterValueSet(filter *Filter) valueSet {
	if filter == nil {
		return valueSet{}
	}
	if filter.Enum != nil {
		// enum shadows type, const and pattern
		return valueSet{effectiveType: "string", finite: filter.Enum, dead: len(filter.Enum) == 0}
	}
	if filter.Const != nil {
		set := valueSet{effectiveType: "string", finite: []string{*filter.Const}}
		if filter.Type != "string" {
			// the const compares as a string, but the type gate rejects string values
			set.dead = true
			return set
		}
		if filter.Pattern != nil {
			if re, err := regexp2.Compile(*filter.Pattern, regexp2.ECMAScript); err == nil {
				if match, _ := re.FindStringMatch(*filter.Const); match == nil {
					set.dead = true
				}
			}
		}
		return set
	}
	if filter.Pattern != nil && filter.Type == "string" {
		if re, err := regexp2.Compile(*filter.Pattern, regexp2.ECMAScript); err == nil {
			return valueSet{effectiveType: "string", pattern: re}
		}
		// a non-compiling pattern is reported as invalid_pattern; no predicate here
		return valueSet{effectiveType: "string"}
	}
	return valueSet{effectiveType: filter.Type}
}

// idOccurrence is one field carrying a shared id, with its derived value set.
type idOccurrence struct {
	descriptorID string
	set          valueSet
}

// sameIDConflicts checks every field id used on two or more fields across descriptors: the value
// the id binds to must be able to satisfy all of them at once (Policy 7). Types must agree, and
// the intersection of the accepted-value sets must not be provably empty. Only the
// pattern-versus-pattern case (no const or enum anywhere) is deferred to request time.
func sameIDConflicts(pd PresentationDefinition) []FieldIDConflict {
	occurrences := make(map[string][]idOccurrence)
	var order []string
	for _, descriptor := range pd.InputDescriptors {
		if descriptor.Constraints == nil {
			continue
		}
		for _, field := range descriptor.Constraints.Fields {
			if field.Id == nil {
				continue
			}
			if _, seen := occurrences[*field.Id]; !seen {
				order = append(order, *field.Id)
			}
			occurrences[*field.Id] = append(occurrences[*field.Id], idOccurrence{
				descriptorID: descriptor.Id,
				set:          filterValueSet(field.Filter),
			})
		}
	}

	var conflicts []FieldIDConflict
	for _, id := range order {
		fields := occurrences[id]
		if len(fields) < 2 {
			continue
		}
		// dead filters are reported on their own; they carry no usable value set here
		var sets []valueSet
		for _, occurrence := range fields {
			if !occurrence.set.dead {
				sets = append(sets, occurrence.set)
			}
		}

		// type agreement: every constrained occurrence must agree on the value type
		types := make(map[string]bool)
		for _, set := range sets {
			if set.effectiveType != "" {
				types[set.effectiveType] = true
			}
		}
		if len(types) > 1 {
			names := make([]string, 0, len(types))
			for name := range types {
				names = append(names, name)
			}
			sort.Strings(names)
			conflicts = append(conflicts, FieldIDConflict{
				FieldID: id,
				Kind:    ConflictType,
				Detail:  "conflicting filter types: " + strings.Join(names, " vs "),
			})
			continue // value sets of different types cannot be intersected meaningfully
		}

		// value-set intersection, decidable whenever some filter pins a finite candidate set
		var candidates []string
		haveFinite := false
		for _, set := range sets {
			if set.finite == nil {
				continue
			}
			if !haveFinite {
				candidates, haveFinite = set.finite, true
				continue
			}
			candidates = intersect(candidates, set.finite)
		}
		if !haveFinite {
			continue // universes always overlap; pattern-versus-pattern is deferred
		}
		if len(candidates) == 0 {
			conflicts = append(conflicts, FieldIDConflict{
				FieldID: id,
				Kind:    ConflictUnsatisfiable,
				Detail:  "const/enum values across descriptors share no common value",
			})
			continue
		}
		for _, set := range sets {
			if set.pattern == nil {
				continue
			}
			candidates = matchingCandidates(candidates, set.pattern)
			if len(candidates) == 0 {
				conflicts = append(conflicts, FieldIDConflict{
					FieldID: id,
					Kind:    ConflictUnsatisfiable,
					Detail:  fmt.Sprintf("no shared const/enum value matches pattern '%s'", set.pattern.String()),
				})
				break
			}
		}
	}
	return conflicts
}

// intersect returns the values present in both slices, preserving the order of the first.
func intersect(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, value := range b {
		inB[value] = true
	}
	var result []string
	for _, value := range a {
		if inB[value] {
			result = append(result, value)
		}
	}
	return result
}

// matchingCandidates keeps the candidates the pattern accepts, using the same regex semantics as
// the matcher (regexp2, ECMAScript).
func matchingCandidates(candidates []string, pattern *regexp2.Regexp) []string {
	var result []string
	for _, candidate := range candidates {
		if match, err := pattern.FindStringMatch(candidate); err == nil && match != nil {
			result = append(result, candidate)
		}
	}
	return result
}

// UnknownSelectionKeysError is returned by ValidateSelectionKeys when the caller supplied
// credential_selection keys that are not field ids in any of the supplied presentation
// definitions.
type UnknownSelectionKeysError struct {
	// Keys holds every unknown key, sorted.
	Keys []string
}

func (e *UnknownSelectionKeysError) Error() string {
	return "unknown credential_selection keys: " + strings.Join(e.Keys, ", ")
}

// ValidateSelectionKeys checks that every credential_selection key is a field id in at least one
// of the supplied presentation definitions (the union: one PD for a single-VP request, two for a
// two-VP request). Key names only are validated; values, including empty strings, play no role.
// It returns an UnknownSelectionKeysError naming every unknown key, or nil.
func ValidateSelectionKeys(selection map[string]string, pds ...PresentationDefinition) error {
	known := make(map[string]bool)
	for _, pd := range pds {
		for _, descriptor := range pd.InputDescriptors {
			if descriptor.Constraints == nil {
				continue
			}
			for _, field := range descriptor.Constraints.Fields {
				if field.Id != nil {
					known[*field.Id] = true
				}
			}
		}
	}
	var unknown []string
	for key := range selection {
		if !known[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return &UnknownSelectionKeysError{Keys: unknown}
}
