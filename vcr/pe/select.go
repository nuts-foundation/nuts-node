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

// SelectionStrategy controls what Select does when more than one complete, binding-consistent
// assignment exists. It gates only the ambiguity policy; binding consistency itself is always on.
type SelectionStrategy int

const (
	// FirstMatch takes the first consistent assignment (the lenient, backward-compatible default).
	FirstMatch SelectionStrategy = iota
	// Strict returns ErrMultipleCredentials when a rival assignment exists: one that fills a
	// common descriptor with a different binding tuple. Interchangeable credentials are never
	// rivals, since no credential_selection key could separate them.
	Strict
)

// selectOptions holds the knobs configured by the Option functions passed to Select.
type selectOptions struct {
	// initialBindings seeds the id->value bindings (typically from a credential_selection parameter).
	initialBindings map[string]string
	// strategy selects the ambiguity policy; the zero value is FirstMatch.
	strategy SelectionStrategy
	// trace enables the MatchReport diagnostics.
	trace bool
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

// WithStrategy selects the ambiguity policy; the default is FirstMatch.
func WithStrategy(s SelectionStrategy) Option {
	return func(o *selectOptions) {
		o.strategy = s
	}
}

// WithSelectionTrace populates Result.Report with a MatchReport explaining, per descriptor, why
// each candidate was or wasn't selected. Off by default; a non-traced run pays nothing for it.
func WithSelectionTrace() Option {
	return func(o *selectOptions) {
		o.trace = true
	}
}

// Result is the outcome of a Select call.
type Result struct {
	// Candidates pairs every input descriptor (in PD order) with the VC chosen for it, on every
	// path including errors (best-effort on failure, for diagnostics).
	// A nil VC means the descriptor was left unfilled (optional and skipped, dropped by a rule,
	// or unfillable).
	Candidates []Candidate
	// Bindings holds the id-to-value pairs resolved by the surviving credentials of the
	// decisive assignment, for chaining into a next Select (the two-VP composition) or for
	// reporting. Nil when Select returns an error.
	Bindings map[string]string
	// Report explains the selection per descriptor; non-nil only under WithSelectionTrace.
	Report *MatchReport
}

// Select resolves a presentation definition against a set of candidate credentials and
// returns the chosen descriptor-to-VC assignment. It is the single matching engine: it
// determines each descriptor's eligible credentials (step 1), searches for an assignment with
// consistent bindings (step 2), and applies the submission requirement rules (step 3).
//
// The vocabulary (binding, caller-bound, interchangeable, decisive assignment) is defined in
// the package documentation. The search follows these rules:
//
//   - Binding consistency: equal field ids resolve to equal values in the chosen assignment,
//     across descriptors and against the initial bindings.
//   - Prefer fill over skip: an optional descriptor is left unfilled only after all its
//     consistent candidates are exhausted; a required descriptor with no consistent candidate
//     makes the search revise an earlier choice.
//   - Interchangeability: credentials with identical binding tuples are a single choice; the
//     first in candidate order is used. Fields the PD does not declare play no role.
//   - Caller-bound multiplicity: a caller-bound descriptor must resolve to exactly one
//     interchangeable set; more than one is ErrMultipleCredentials, and the remedy is always a
//     bindable key. The bound field must actually resolve; an unresolved optional field does
//     not satisfy a bound id.
//   - Unresolved optional fields bind nothing: between descriptors, a field that resolves no
//     value contributes no binding entry.
//   - Ambiguity (Strict only): a rival assignment, one that fills a common descriptor with a
//     different binding tuple, is ErrMultipleCredentials instead of a silent pick.
//
// Candidates are expected to be time-valid; the wallet filters expired and revoked credentials
// before calling the engine.
func Select(pd PresentationDefinition, candidates []vc.VerifiableCredential, opts ...Option) (result Result, err error) {
	var options selectOptions
	for _, opt := range opts {
		opt(&options)
	}

	result = Result{Candidates: make([]Candidate, len(pd.InputDescriptors))}
	for i, descriptor := range pd.InputDescriptors {
		result.Candidates[i].InputDescriptor = *descriptor
	}

	required := requiredDescriptors(pd)
	assignment := make([]*candidateGroup, len(pd.InputDescriptors))
	var ambiguous []string
	if options.trace {
		defer func() {
			result.Report = buildReport(pd, candidates, required, assignment, ambiguous, result, err, options.initialBindings)
		}()
	}

	// Step 1: per-descriptor eligibility, indexed for the search.
	pools := make([]descriptorPool, len(pd.InputDescriptors))
	for i, descriptor := range pd.InputDescriptors {
		pool, poolErr := buildPool(pd, *descriptor, candidates)
		if poolErr != nil {
			return result, poolErr
		}
		pool.strictIDs = strictBoundIDs(*descriptor, options.initialBindings)
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
			// the pinned-but-ambiguous descriptors are the report's ambiguous descriptors
			ambiguous = append(ambiguous, pools[i].descriptor.Id)
			if boundErr == nil {
				boundErr = err
			}
		}
	}

	// Step 2: search for a complete binding-consistent assignment.
	found := false
	limited := false
	if boundErr == nil {
		s := &searcher{pools: pools, required: required, strict: options.strategy == Strict}
		s.search(0, copyBindings(options.initialBindings), make([]*candidateGroup, len(pools)))
		found = s.first != nil
		ambiguous = s.ambiguous
		limited = s.limited
		if found {
			copy(assignment, s.first)
		}
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
	if limited {
		// A found-but-unproven assignment is not returned as a success: under Strict that would
		// silently downgrade the ambiguity guarantee.
		return result, fmt.Errorf("presentation definition '%s': search aborted, %w (%d)", pd.Id, ErrSearchLimitReached, searchNodeLimit)
	}
	if len(ambiguous) > 0 {
		// The decisive assignment stays in Candidates so the caller can see what would have won.
		return result, fmt.Errorf("ambiguous input descriptors %v: %w", ambiguous, ErrMultipleCredentials)
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

	// Expose the resolved id-values of the surviving credentials, so a caller can chain them into
	// a next Select (the two-VP composition) or report them.
	result.Bindings = make(map[string]string)
	for i := range assignment {
		if assignment[i] == nil || result.Candidates[i].VC == nil {
			continue
		}
		for id, value := range assignment[i].idValues {
			result.Bindings[id] = value
		}
	}

	return result, nil
}

// ErrSearchLimitReached is returned when the backtracking search exceeds its node-visit limit, a
// defense against pathological (counterparty-supplied) presentation definitions. It is a distinct
// failure class: neither "no credentials" nor "multiple credentials".
var ErrSearchLimitReached = errors.New("search node limit reached")

// searchNodeLimit bounds the number of node visits of a single search. Presentation definitions
// arrive from the counterparty in wallet flows, so an unbounded backtracking search would be
// remotely triggerable CPU exhaustion; legitimate wallets stay orders of magnitude below this.
// A variable so tests can lower it.
var searchNodeLimit = 1_000_000

// searcher carries the inputs and outcome of the step-2 backtracking search.
type searcher struct {
	pools    []descriptorPool
	required []bool
	strict   bool
	// first is the first complete assignment found (the decisive one), nil until then.
	first []*candidateGroup
	// ambiguous holds, under Strict, the descriptors a rival assignment fills differently.
	ambiguous []string
	// visited counts node visits; when it exceeds searchNodeLimit, limited is set and the
	// search unwinds.
	visited int
	limited bool
}

// search explores binding-consistent choices per descriptor, depth-first in PD order, and reports
// whether the caller should stop descending. Candidates are preferred over skipping: an optional
// descriptor is left unfilled (nil) only after all its consistent candidates have been tried; a
// required descriptor with no consistent candidate fails the branch, which backtracks into a
// different choice at an earlier descriptor. The bindings map is mutated during descent and
// restored on backtrack. Under FirstMatch the search stops at the first complete assignment;
// under Strict it continues until a rival assignment is found or the space is exhausted.
func (s *searcher) search(i int, bindings map[string]string, current []*candidateGroup) bool {
	s.visited++
	if s.visited > searchNodeLimit {
		s.limited = true
		return true
	}
	if i == len(s.pools) {
		return s.emit(current)
	}
	for _, gi := range s.pools[i].consistentGroups(bindings) {
		group := &s.pools[i].groups[gi]
		current[i] = group
		added := addBindings(bindings, group.idValues)
		stop := s.search(i+1, bindings, current)
		for _, key := range added {
			delete(bindings, key)
		}
		if stop {
			return true
		}
	}
	current[i] = nil
	if !s.required[i] {
		return s.search(i+1, bindings, current)
	}
	return false
}

// emit records a complete assignment. The first one is kept as the decisive assignment. Under
// Strict, a later assignment is a rival only when it fills a descriptor the first one also fills
// with a different binding tuple: interchangeable credentials share a group and can never differ,
// and a skipped descriptor is not an alternative to a filled one (the skip branch is the
// after-exhaustion path, which keeps either-or pick groups deterministic).
func (s *searcher) emit(current []*candidateGroup) bool {
	if s.first == nil {
		s.first = append([]*candidateGroup(nil), current...)
		return !s.strict
	}
	var ambiguous []string
	for i := range current {
		if s.first[i] != nil && current[i] != nil && s.first[i] != current[i] {
			ambiguous = append(ambiguous, s.pools[i].descriptor.Id)
		}
	}
	if len(ambiguous) > 0 {
		s.ambiguous = ambiguous
		return true
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

// callerBoundError enforces the caller-bound multiplicity rule: a descriptor pinned by the
// caller's bindings must resolve to exactly one interchangeable set of credentials. Counted per
// binding tuple: matches that differ on some other declared field id are distinct choices and the
// error names a real remedy (bind that id too), while matches agreeing on every declared id are
// interchangeable and the first one is used. Zero matches is a soft failure: the descriptor is
// left unfilled and step 3 decides.
func callerBoundError(pool descriptorPool, initialBindings map[string]string) error {
	if len(pool.strictIDs) == 0 {
		return nil
	}
	if len(pool.consistentGroups(initialBindings)) > 1 {
		return fmt.Errorf("input descriptor '%s': %w", pool.descriptor.Id, ErrMultipleCredentials)
	}
	return nil
}

// candidateGroup is a set of credentials that are interchangeable for one descriptor: they passed
// its constraints with identical binding tuples (they are interchangeable). The search branches per
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
	// strictIDs are the descriptor's field ids bound by the caller. For these ids a group must
	// resolve the field to the bound value; unresolved is not acceptable (legacy field-selector
	// semantics). The unresolved-optional leniency covers only bindings accumulated during the search.
	strictIDs []string
}

// strictBoundIDs returns the descriptor's field ids that appear in the caller's initial bindings.
func strictBoundIDs(descriptor InputDescriptor, initialBindings map[string]string) []string {
	if descriptor.Constraints == nil {
		return nil
	}
	var ids []string
	for _, field := range descriptor.Constraints.Fields {
		if field.Id == nil {
			continue
		}
		if _, ok := initialBindings[*field.Id]; ok {
			ids = append(ids, *field.Id)
		}
	}
	return ids
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
// every shared id. Bound ids outside the pool's universe are irrelevant, except strict ids, which
// a group must resolve to the bound value. When at least one bound id is in the universe, the scan
// is narrowed to the smallest posting list (groups carrying the bound value, plus, for non-strict
// ids, groups not resolving the id at all) before the full per-group check.
func (p descriptorPool) consistentGroups(bindings map[string]string) []int {
	var narrowed []int
	haveNarrowed := false
	for _, id := range p.strictIDs {
		bound, ok := bindings[id]
		if !ok {
			continue
		}
		// no lacking-list here: a group that does not resolve a strict id is out
		list := p.byValue[id][bound]
		if len(list) == 0 {
			return nil
		}
		if !haveNarrowed || len(list) < len(narrowed) {
			narrowed, haveNarrowed = list, true
		}
	}
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
		group := p.groups[gi]
		if !consistentIDValues(group.idValues, bindings) {
			continue
		}
		if !resolvesStrictIDs(group, p.strictIDs) {
			continue
		}
		consistent = append(consistent, gi)
	}
	return consistent
}

// resolvesStrictIDs reports whether the group resolves every strictly bound id. Equality with the
// bound value is covered by the consistency check; this guards only against unresolved fields.
func resolvesStrictIDs(group candidateGroup, strictIDs []string) bool {
	for _, id := range strictIDs {
		if _, ok := group.idValues[id]; !ok {
			return false
		}
	}
	return true
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

	// Keep each selected credential on the first descriptor that carries it (PD order) and clear
	// the rest. The rules select credentials, not descriptors: consuming the selection prevents a
	// credential that fills several descriptors from multiplying past the rule's count, and
	// matches the legacy first-descriptor mapping.
	remaining := selectedVCs
	result := make([]Candidate, len(candidates))
	for i, candidate := range candidates {
		result[i] = candidate
		result[i].VC = nil
		if candidate.VC == nil {
			continue
		}
		for j, selected := range remaining {
			if vcEqual(selected, *candidate.VC) {
				result[i].VC = candidate.VC
				remaining = append(remaining[:j], remaining[j+1:]...)
				break
			}
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

// eligibleCandidate is a credential that passed a descriptor on its own (step 1), paired with the
// field-id -> value bindings it resolves. The bindings drive cross-descriptor consistency.
type eligibleCandidate struct {
	vc       vc.VerifiableCredential
	idValues map[string]string
}

// eligibleCandidates returns the credentials that satisfy a single input descriptor on its own:
// its constraints (matchConstraint) and both the PD-level and descriptor-level format gates. The
// resolved field-id values are recorded (stringified) as the candidate's binding tuple.
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
