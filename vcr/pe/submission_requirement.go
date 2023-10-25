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
	selectedVCs := make([]vc.VerifiableCredential, 0)
	group := availableGroups[submissionRequirement.From]
	// different rules for 'all' and 'pick'
	switch submissionRequirement.Rule {
	case "all":
		// all means all matches in the group must be in the submission
		// if any of the Match has an empty VC, we return an empty submission
		for _, match := range group.Candidates {
			if match.VC == nil {
				return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from the group", submissionRequirement.Name)
			}
			selectedVCs = append(selectedVCs, *match.VC)
		}
		return selectedVCs, nil
	case "pick":
		// pick means we need to pick one or more of the matches
		// count number of matches with VC
		var count int
		for _, match := range group.Candidates {
			if match.VC != nil {
				count++
			}
		}
		// check count
		if submissionRequirement.Count != nil {
			if count < *submissionRequirement.Count {
				return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than required (%d)", submissionRequirement.Name, count, *submissionRequirement.Count)
			}
			i := 0

			for _, match := range group.Candidates {
				if match.VC != nil {
					selectedVCs = append(selectedVCs, *match.VC)
					i++
				}
				if i == *submissionRequirement.Count {
					break
				}
			}
			return selectedVCs, nil
		}
		// check min and max
		if submissionRequirement.Min != nil && count < *submissionRequirement.Min {
			return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than minimal required (%d)", submissionRequirement.Name, count, *submissionRequirement.Min)
		}
		// take min if both min and max are set
		index := 0
		for _, match := range group.Candidates {
			if match.VC != nil {
				selectedVCs = append(selectedVCs, *match.VC)
				index++
			}
			if index == *submissionRequirement.Max {
				break
			}
		}
		return selectedVCs, nil
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}

func (submissionRequirement SubmissionRequirement) fromNested(availableGroups map[string]GroupCandidates) ([]vc.VerifiableCredential, error) {
	selectedVCs := make([][]vc.VerifiableCredential, len(submissionRequirement.FromNested))
	for i, nested := range submissionRequirement.FromNested {
		vcs, err := nested.match(availableGroups)
		if err != nil {
			if submissionRequirement.Rule == "all" {
				// exit early
				return nil, fmt.Errorf("submission requirement (%s) does not have all credentials from nested requirements", submissionRequirement.Name)
			}
			continue
		}
		selectedVCs[i] = vcs
	}
	switch submissionRequirement.Rule {
	case "all":
		var returnVCs []vc.VerifiableCredential
		for _, vcs := range selectedVCs {
			returnVCs = append(returnVCs, vcs...)
		}
		return returnVCs, nil
	case "pick":
		var returnVCs []vc.VerifiableCredential
		// pick means we need to pick one or more of the nested sets
		var count int
		for _, set := range selectedVCs {
			if len(set) > 0 {
				count++
			}
		}
		// check count
		if submissionRequirement.Count != nil {
			if count < *submissionRequirement.Count {
				return nil, fmt.Errorf("submission requirement (%s) has less credentials (%d) than requried (%d)", submissionRequirement.Name, count, *submissionRequirement.Count)
			}
			i := 0
			for _, set := range selectedVCs {
				if len(set) > 0 {
					returnVCs = append(returnVCs, set...)
					i++
				}
				if i == *submissionRequirement.Count {
					break
				}
			}
			return returnVCs, nil
		}
		// check min and max
		if submissionRequirement.Min != nil && count < *submissionRequirement.Min {
			return nil, fmt.Errorf("submission requirement (%s) has less matches (%d) than minimal required (%d)", submissionRequirement.Name, count, *submissionRequirement.Min)
		}
		// take max if both min and max are set
		index := 0
		for _, set := range selectedVCs {
			if len(set) > 0 {
				returnVCs = append(returnVCs, set...)
				index++
			}
			if index == *submissionRequirement.Max {
				break
			}
		}
		return returnVCs, nil
	default:
		return nil, fmt.Errorf("submission requirement (%s) contains unknown rule (%s)", submissionRequirement.Name, submissionRequirement.Rule)
	}
}
