/*
 * Copyright (C) 2023 Nuts community
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
	"github.com/nuts-foundation/go-did/vc"
	"slices"
)

// groupCandidates is a struct that holds all InputDescriptor/VC candidates for a group
type groupCandidates struct {
	Name       string
	Candidates []Candidate
}

// groups returns all the group names from the 'from' field. It traverses the 'from_nested' field recursively.
func (submissionRequirement SubmissionRequirement) groups() []string {
	var result []string
	if submissionRequirement.From != "" {
		result = append(result, submissionRequirement.From)
	}
	for _, nested := range submissionRequirement.FromNested {
		result = append(result, nested.groups()...)
	}
	//deduplicate by using sort and compact
	slices.Sort(result)
	return slices.Compact(result)
}

func (submissionRequirement SubmissionRequirement) match(availableGroups map[string]groupCandidates) ([]vc.VerifiableCredential, error) {
	if submissionRequirement.From != "" && len(submissionRequirement.FromNested) > 0 {
		return nil, fmt.Errorf("submission requirement (%s) contains both 'from' and 'from_nested'", submissionRequirement.Name)
	}
	if submissionRequirement.From == "" && len(submissionRequirement.FromNested) == 0 {
		return nil, fmt.Errorf("submission requirement (%s) is missing 'from' or 'from_nested'", submissionRequirement.Name)
	}

	if !(submissionRequirement.Rule == "all" || submissionRequirement.Rule == "pick") {
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}

	if len(submissionRequirement.FromNested) > 0 {
		return submissionRequirement.fromNested(availableGroups)
	}
	return submissionRequirement.from(availableGroups)
}

func (submissionRequirement SubmissionRequirement) from(availableGroups map[string]groupCandidates) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([]selectableVC, 0)
	group := availableGroups[submissionRequirement.From]
	for _, match := range group.Candidates {
		if match.VC != nil {
			selectedVCs = append(selectedVCs, selectableVC(*match.VC))
		} else {
			selectedVCs = append(selectedVCs, selectableVC(vc.VerifiableCredential{}))
		}
	}

	return apply(selectedVCs, submissionRequirement)
}

func (submissionRequirement SubmissionRequirement) fromNested(availableGroups map[string]groupCandidates) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([]selectableVCList, len(submissionRequirement.FromNested))
	for i, nested := range submissionRequirement.FromNested {
		vcs, err := nested.match(availableGroups)
		if err != nil {
			continue
		}
		selectedVCs[i] = vcs
	}
	return apply(selectedVCs, submissionRequirement)
}

// selectable is a helper interface to determine if an entry can be selected for a SubmissionRequirement.
// If it's non-empty then it can be used for counting.
// This interface is used as slices, empty places in these slices have a meaning.
type selectable interface {
	empty() bool
	flatten() []vc.VerifiableCredential
}

type selectableVC vc.VerifiableCredential

type selectableVCList []vc.VerifiableCredential

func (v selectableVC) empty() bool {
	return len(v.CredentialSubject) == 0 && v.ID == nil && len(v.Type) == 0
}

func (v selectableVC) flatten() []vc.VerifiableCredential {
	return []vc.VerifiableCredential{vc.VerifiableCredential(v)}
}

func (v selectableVCList) empty() bool {
	return len(v) == 0
}

func (v selectableVCList) flatten() []vc.VerifiableCredential {
	var returnVCs []vc.VerifiableCredential
	for _, selection := range v {
		returnVCs = append(returnVCs, selection)
	}
	return returnVCs
}

func apply[S ~[]E, E selectable](list S, submissionRequirement SubmissionRequirement) ([]vc.VerifiableCredential, error) {
	var returnVCs []vc.VerifiableCredential
	// count the non-nil/non-empty members
	// an empty member means that the constraints did not match for that group member
	var selectableCount int
	for _, member := range list {
		if !member.empty() {
			selectableCount++
		}
	}
	// check "all" rule
	if submissionRequirement.Rule == "all" {
		// no empty members allowed
		if selectableCount != len(list) {
			return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from the group", submissionRequirement.Name)
		}
		for _, member := range list {
			// shouldn't happen, but prevents a panic
			if !member.empty() {
				returnVCs = append(returnVCs, member.flatten()...)
			}
		}
		return returnVCs, nil
	}

	// check "count" rule
	if submissionRequirement.Count != nil {
		// not enough matching constraints
		if selectableCount < *submissionRequirement.Count {
			return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than required (%d)", submissionRequirement.Name, selectableCount, *submissionRequirement.Count)
		}
		i := 0
		for _, member := range list {
			if !member.empty() {
				returnVCs = append(returnVCs, member.flatten()...)
				i++
			}
			if i == *submissionRequirement.Count {
				// we have enough to fulfill the count requirement, stop
				break
			}
		}
		return returnVCs, nil
	}
	// check min and max rules
	// only check if min requirement is met, max just determines the upper bound for the return
	if submissionRequirement.Min != nil && selectableCount < *submissionRequirement.Min {
		return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than minimal required (%d)", submissionRequirement.Name, selectableCount, *submissionRequirement.Min)
	}
	// take max if both min and max are set
	index := 0
	for _, member := range list {
		if !member.empty() {
			returnVCs = append(returnVCs, member.flatten()...)
			index++
		}
		if index == *submissionRequirement.Max {
			// we have enough to fulfill the max requirement, stop
			break
		}
	}
	return returnVCs, nil
}
