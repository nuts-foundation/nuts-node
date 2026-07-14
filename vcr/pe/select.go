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
	"sort"
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
	// Candidates pairs every input descriptor (in PD order) with the VC chosen for it, on every
	// path including errors (best-effort on failure, for diagnostics).
	// A nil VC means the descriptor was left unfilled (optional and skipped, dropped by a rule,
	// or unfillable).
	Candidates []Candidate
	// Bindings holds the resolved field-id to value pairs of the chosen assignment.
	Bindings map[string]string
}

// Select resolves a presentation definition against a set of candidate credentials and
// returns the chosen descriptor-to-VC assignment. It is the single matching engine: it
// matches each descriptor on its own (step 1), searches for a binding-consistent combination
// across descriptors (step 2), and applies the submission requirement rules (step 3).
func Select(pd PresentationDefinition, candidates []vc.VerifiableCredential, opts ...Option) (Result, error) {
	var options selectOptions
	for _, opt := range opts {
		opt(&options)
	}

	result := Result{Candidates: make([]Candidate, len(pd.InputDescriptors))}
	for i, descriptor := range pd.InputDescriptors {
		result.Candidates[i].InputDescriptor = *descriptor
	}

	// Step 1: per-descriptor eligibility, indexed for the search.
	pools := make([]descriptorPool, len(pd.InputDescriptors))
	for i, descriptor := range pd.InputDescriptors {
		pool, err := buildPool(pd, *descriptor, candidates)
		if err != nil {
			return result, err
		}
		pools[i] = pool
	}

	// A descriptor pinned by the caller's bindings must resolve to exactly one credential (the
	// legacy field-selector contract). This is a per-descriptor check against the initial
	// bindings only; it is deliberately separate from the whole-assignment ambiguity check.
	var boundErr error
	boundFailed := make([]bool, len(pools))
	for i := range pools {
		if err := callerBoundError(pools[i], options.initialBindings); err != nil {
			boundFailed[i] = true
			if boundErr == nil {
				boundErr = err
			}
		}
	}

	// Step 2: search for a complete binding-consistent assignment.
	assignment := make([]*candidateGroup, len(pools))
	found := false
	if boundErr == nil {
		s := searcher{pools: pools, required: requiredDescriptors(pd)}
		found = s.search(0, copyBindings(options.initialBindings), assignment)
	}
	if !found {
		// Best-effort assignment for diagnostics: each descriptor on its own, first candidate
		// consistent with the initial bindings.
		for i := range pools {
			assignment[i] = nil
			if boundFailed[i] {
				continue
			}
			if groups := pools[i].consistentGroups(options.initialBindings); len(groups) > 0 {
				assignment[i] = &pools[i].groups[groups[0]]
			}
		}
	}
	for i := range assignment {
		if assignment[i] != nil {
			result.Candidates[i].VC = &assignment[i].creds[0]
		}
	}
	if boundErr != nil {
		return result, boundErr
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
	if !found {
		// The search proved no consistent assignment exists; the diagnostic assignment satisfying
		// the rules anyway (possible once bindings conflict across descriptors) is not a success.
		return result, fmt.Errorf("no binding-consistent assignment found: %w", ErrNoCredentials)
	}

	return result, nil
}

// searcher carries the immutable inputs of the step-2 backtracking search.
type searcher struct {
	pools    []descriptorPool
	required []bool
}

// search fills assignment[i:] with a binding-consistent choice per descriptor, depth-first in PD
// order, and reports whether a complete assignment was found. Candidates are preferred over
// skipping: an optional descriptor is left unfilled (nil) only after all its consistent candidates
// have been tried; a required descriptor with no consistent candidate fails the branch, which
// backtracks into a different choice at an earlier descriptor. The bindings map is mutated during
// descent and restored on backtrack.
func (s searcher) search(i int, bindings map[string]string, assignment []*candidateGroup) bool {
	if i == len(s.pools) {
		return true
	}
	for _, gi := range s.pools[i].consistentGroups(bindings) {
		group := &s.pools[i].groups[gi]
		assignment[i] = group
		added := addBindings(bindings, group.idValues)
		if s.search(i+1, bindings, assignment) {
			return true
		}
		for _, key := range added {
			delete(bindings, key)
		}
	}
	assignment[i] = nil
	if !s.required[i] {
		return s.search(i+1, bindings, assignment)
	}
	return false
}

// addBindings merges a chosen candidate's id-values into the running bindings and returns the keys
// it actually added, so the caller can restore the map on backtrack. Keys already bound are left
// untouched: the candidate passed the consistency check, so its values agree.
func addBindings(bindings map[string]string, idValues map[string]string) []string {
	var added []string
	for key, value := range idValues {
		if _, bound := bindings[key]; !bound {
			bindings[key] = value
			added = append(added, key)
		}
	}
	return added
}

// requiredDescriptors derives, per input descriptor, whether the search must fill it. This is the
// coarse rule: with no submission requirements every descriptor is required; otherwise only
// descriptors whose group is demanded in full by an "all" rule are required. Members of "pick"
// groups may be left unfilled by the search; whether enough of them were filled is checked by the
// rule engine in step 3 (the documented pick-min-floor deferral).
func requiredDescriptors(pd PresentationDefinition) []bool {
	required := make([]bool, len(pd.InputDescriptors))
	if len(pd.SubmissionRequirements) == 0 {
		for i := range required {
			required[i] = true
		}
		return required
	}
	allGroups := make(map[string]bool)
	var collect func(requirement SubmissionRequirement)
	collect = func(requirement SubmissionRequirement) {
		if requirement.Rule != "all" {
			// members under a "pick" are selectable, never individually required
			return
		}
		if requirement.From != "" {
			allGroups[requirement.From] = true
		}
		for _, nested := range requirement.FromNested {
			collect(*nested)
		}
	}
	for _, requirement := range pd.SubmissionRequirements {
		collect(*requirement)
	}
	for i, descriptor := range pd.InputDescriptors {
		for _, group := range descriptor.Group {
			if allGroups[group] {
				required[i] = true
				break
			}
		}
	}
	return required
}

// callerBoundError reproduces the legacy field-selector contract: a descriptor pinned by the
// caller's bindings must resolve to exactly one credential; more than one is
// ErrMultipleCredentials. Counted per credential (not per binding tuple), because that is the
// behavior existing callers rely on. Zero matches is a soft failure: the descriptor is left
// unfilled and step 3 decides.
func callerBoundError(pool descriptorPool, initialBindings map[string]string) error {
	if !isCallerBound(pool.descriptor, initialBindings) {
		return nil
	}
	count := 0
	for _, gi := range pool.consistentGroups(initialBindings) {
		count += len(pool.groups[gi].creds)
	}
	if count > 1 {
		return fmt.Errorf("input descriptor '%s': %w", pool.descriptor.Id, ErrMultipleCredentials)
	}
	return nil
}

// candidateGroup is a set of credentials that are interchangeable for one descriptor: they passed
// its constraints and resolve identical values for every id-bearing field. The search branches per
// group, not per credential; creds[0] represents the group in the final assignment.
type candidateGroup struct {
	idValues map[string]string
	creds    []vc.VerifiableCredential // in candidate order
}

// descriptorPool is the step-1 output for one descriptor: its eligible credentials grouped by
// binding tuple, with inverted indexes so that consistency filtering during the search is a lookup
// instead of a scan over the pool.
type descriptorPool struct {
	descriptor InputDescriptor
	groups     []candidateGroup
	// byValue maps field id -> resolved value -> ascending indices of groups carrying that value.
	// Its key set is the pool's id universe: ids resolved by at least one group.
	byValue map[string]map[string][]int
	// lacking maps field id (from the same universe) -> ascending indices of groups that do not
	// resolve the id. Such groups are consistent with any bound value for it.
	lacking map[string][]int
}

// buildPool evaluates every candidate against a single input descriptor (its constraints and both
// format gates) and indexes the eligible ones. This is step 1, independent of any cross-descriptor
// binding.
func buildPool(pd PresentationDefinition, descriptor InputDescriptor, candidates []vc.VerifiableCredential) (descriptorPool, error) {
	eligible, err := eligibleCandidates(pd, descriptor, candidates)
	if err != nil {
		return descriptorPool{}, err
	}
	pool := descriptorPool{
		descriptor: descriptor,
		byValue:    make(map[string]map[string][]int),
		lacking:    make(map[string][]int),
	}
	groupIndex := make(map[string]int)
	for _, candidate := range eligible {
		key := tupleKey(candidate.idValues)
		gi, ok := groupIndex[key]
		if !ok {
			gi = len(pool.groups)
			groupIndex[key] = gi
			pool.groups = append(pool.groups, candidateGroup{idValues: candidate.idValues})
		}
		pool.groups[gi].creds = append(pool.groups[gi].creds, candidate.vc)
	}
	for gi, group := range pool.groups {
		for id, value := range group.idValues {
			values := pool.byValue[id]
			if values == nil {
				values = make(map[string][]int)
				pool.byValue[id] = values
			}
			values[value] = append(values[value], gi)
		}
	}
	for id := range pool.byValue {
		for gi, group := range pool.groups {
			if _, ok := group.idValues[id]; !ok {
				pool.lacking[id] = append(pool.lacking[id], gi)
			}
		}
	}
	return pool, nil
}

// consistentGroups returns the ascending indices of the groups that agree with the bindings on
// every shared id. Bound ids outside the pool's universe are irrelevant. When at least one bound
// id is in the universe, the scan is narrowed to the smallest posting list (groups carrying the
// bound value, plus groups not resolving the id at all) before the full per-group check.
func (p descriptorPool) consistentGroups(bindings map[string]string) []int {
	var narrowed []int
	haveNarrowed := false
	for id, value := range bindings {
		values, known := p.byValue[id]
		if !known {
			continue
		}
		merged := mergeSorted(values[value], p.lacking[id])
		if !haveNarrowed || len(merged) < len(narrowed) {
			narrowed, haveNarrowed = merged, true
		}
	}
	if !haveNarrowed {
		all := make([]int, len(p.groups))
		for i := range all {
			all[i] = i
		}
		return all
	}
	var consistent []int
	for _, gi := range narrowed {
		if consistentIDValues(p.groups[gi].idValues, bindings) {
			consistent = append(consistent, gi)
		}
	}
	return consistent
}

// consistentIDValues reports whether resolved id-values agree with the bindings on every shared
// id. An id one side does not carry is irrelevant, so a stray binding key has no effect.
func consistentIDValues(idValues map[string]string, bindings map[string]string) bool {
	for id, value := range idValues {
		if bound, ok := bindings[id]; ok && bound != value {
			return false
		}
	}
	return true
}

// mergeSorted merges two ascending, disjoint index slices into one ascending slice.
func mergeSorted(a, b []int) []int {
	merged := make([]int, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] < b[j] {
			merged = append(merged, a[i])
			i++
		} else {
			merged = append(merged, b[j])
			j++
		}
	}
	merged = append(merged, a[i:]...)
	merged = append(merged, b[j:]...)
	return merged
}

// tupleKey renders id-values as a canonical string so credentials with identical binding tuples
// land in the same group.
func tupleKey(idValues map[string]string) string {
	ids := make([]string, 0, len(idValues))
	for id := range idValues {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var builder strings.Builder
	for _, id := range ids {
		builder.WriteString(strconv.Quote(id))
		builder.WriteByte(':')
		builder.WriteString(strconv.Quote(idValues[id]))
		builder.WriteByte(',')
	}
	return builder.String()
}

// copyBindings clones the initial bindings so the search can mutate its working map freely.
func copyBindings(bindings map[string]string) map[string]string {
	copied := make(map[string]string, len(bindings))
	for key, value := range bindings {
		copied[key] = value
	}
	return copied
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
// its constraints (matchConstraint) and both the PD-level and descriptor-level format gates. The
// matched id-bearing field values are recorded (stringified) for later consistency checks.
func eligibleCandidates(pd PresentationDefinition, descriptor InputDescriptor, candidates []vc.VerifiableCredential) ([]eligibleCandidate, error) {
	var eligible []eligibleCandidate
	for _, candidate := range candidates {
		idValues := make(map[string]string)
		if descriptor.Constraints != nil {
			isMatch, values, err := matchConstraint(descriptor.Constraints, candidate)
			if err != nil {
				return nil, err
			}
			if !isMatch {
				continue
			}
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
