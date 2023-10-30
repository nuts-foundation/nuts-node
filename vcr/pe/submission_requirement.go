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

// GroupCandidates is a struct that holds all InputDescriptor/VC candidates for a group
type GroupCandidates struct {
	Name       string
	Candidates []Candidate
}

// Groups returns all the group names from the 'from' field. It traverses the 'from_nested' field recursively.
func (submissionRequirement SubmissionRequirement) Groups() []string {
	result := []string{}
	if submissionRequirement.From != "" {
		result = append(result, submissionRequirement.From)
	}
	for _, nested := range submissionRequirement.FromNested {
		result = append(result, nested.Groups()...)
	}
	//deduplicate by using sort and compact
	slices.Sort(result)
	return slices.Compact(result)
}

func (submissionRequirement SubmissionRequirement) match(availableGroups map[string]GroupCandidates) ([]vc.VerifiableCredential, error) {
	if submissionRequirement.From != "" && len(submissionRequirement.FromNested) > 0 {
		return nil, fmt.Errorf("submission requirement (%s) contains both 'from' and 'from_nested'", submissionRequirement.Name)
	}

	if len(submissionRequirement.FromNested) > 0 {
		return submissionRequirement.fromNested(availableGroups)
	}
	return submissionRequirement.from(availableGroups)
}

func (submissionRequirement SubmissionRequirement) from(availableGroups map[string]GroupCandidates) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([]pickableVC, 0)
	group := availableGroups[submissionRequirement.From]
	for _, match := range group.Candidates {
		if match.VC != nil {
			selectedVCs = append(selectedVCs, pickableVC(*match.VC))
		}
	}
	// different rules for 'all' and 'pick'
	switch submissionRequirement.Rule {
	case "all":
		if len(selectedVCs) != len(group.Candidates) {
			return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from the group", submissionRequirement.Name)
		}
		returnVCs := make([]vc.VerifiableCredential, len(selectedVCs))
		for i, selectedVC := range selectedVCs {
			returnVCs[i] = vc.VerifiableCredential(selectedVC)
		}
		return returnVCs, nil
	case "pick":
		return pick(selectedVCs, submissionRequirement)
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}

func (submissionRequirement SubmissionRequirement) fromNested(availableGroups map[string]GroupCandidates) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([]pickableVCList, len(submissionRequirement.FromNested))
	for i, nested := range submissionRequirement.FromNested {
		vcs, err := nested.match(availableGroups)
		if err != nil {
			if submissionRequirement.Rule == "all" {
				return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from nested requirements", submissionRequirement.Name)
			}
			continue
		}
		selectedVCs[i] = vcs
	}
	switch submissionRequirement.Rule {
	case "all":
		returnVCs := make([]vc.VerifiableCredential, 0)
		for _, selectedVC := range selectedVCs {
			returnVCs = append(returnVCs, selectedVC.flatten()...)
		}
		return returnVCs, nil
	case "pick":
		return pick(selectedVCs, submissionRequirement)
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}

type pickable interface {
	empty() bool
	flatten() []vc.VerifiableCredential
}

type pickableVC vc.VerifiableCredential

type pickableVCList []vc.VerifiableCredential

func (v pickableVC) empty() bool {
	return false
}

func (v pickableVC) flatten() []vc.VerifiableCredential {
	return []vc.VerifiableCredential{vc.VerifiableCredential(v)}
}

func (v pickableVCList) empty() bool {
	return len(v) == 0
}

func (v pickableVCList) flatten() []vc.VerifiableCredential {
	var returnVCs []vc.VerifiableCredential
	for _, selection := range v {
		returnVCs = append(returnVCs, selection)
	}
	return returnVCs
}

func pick[S ~[]E, E pickable](list S, submissionRequirement SubmissionRequirement) ([]vc.VerifiableCredential, error) {
	var returnVCs []vc.VerifiableCredential
	// check for non-empty members
	var size int
	for _, member := range list {
		if !member.empty() {
			size++
		}
	}
	// check count
	if submissionRequirement.Count != nil {
		if size < *submissionRequirement.Count {
			return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than required (%d)", submissionRequirement.Name, size, *submissionRequirement.Count)
		}
		i := 0
		for _, member := range list {
			if !member.empty() {
				returnVCs = append(returnVCs, member.flatten()...)
				i++
			}
			if i == *submissionRequirement.Count {
				break
			}
		}
		return returnVCs, nil
	}
	// check min and max
	if submissionRequirement.Min != nil && size < *submissionRequirement.Min {
		return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than minimal required (%d)", submissionRequirement.Name, size, *submissionRequirement.Min)
	}
	// take max if both min and max are set
	index := 0
	for _, member := range list {
		if !member.empty() {
			returnVCs = append(returnVCs, member.flatten()...)
			index++
		}
		if index == *submissionRequirement.Max {
			break
		}
	}
	return returnVCs, nil
}
