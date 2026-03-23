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
	"encoding/json"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_match(t *testing.T) {
	t.Run("error - submission requirement with both from and from_nested", func(t *testing.T) {
		submissionRequirement := SubmissionRequirement{
			Name:       "test",
			From:       "A",
			FromNested: []*SubmissionRequirement{{Name: "test"}},
		}
		availableGroups := map[string]groupCandidates{}
		_, err := submissionRequirement.match(availableGroups)
		require.Error(t, err)
		assert.EqualError(t, err, "submission requirement (test) contains both 'from' and 'from_nested'")
	})
}

func TestSubmissionRequirement_Groups(t *testing.T) {
	t.Run("group from a single requirement", func(t *testing.T) {
		requirement := SubmissionRequirement{
			From: "A",
		}

		groups := requirement.groups()

		assert.Equal(t, []string{"A"}, groups)
	})
	t.Run("groups from nested requirements", func(t *testing.T) {
		requirement := SubmissionRequirement{
			From: "A",
			FromNested: []*SubmissionRequirement{
				{From: "B"},
			},
		}

		groups := requirement.groups()

		assert.Equal(t, []string{"A", "B"}, groups)
	})
	t.Run("deduplicate groups", func(t *testing.T) {
		requirement := SubmissionRequirement{
			From: "A",
			FromNested: []*SubmissionRequirement{
				{From: "B"},
				{From: "A"},
			},
		}

		groups := requirement.groups()

		assert.Equal(t, []string{"A", "B"}, groups)
	})
}

// Helper function to create a simple JSONLD VC
func testVC(id string) vc.VerifiableCredential {
	credential := vc.VerifiableCredential{
		ID: to.Ptr(ssi.MustParseURI(id)),
	}
	bytes, _ := credential.MarshalJSON()
	var result vc.VerifiableCredential
	_ = json.Unmarshal(bytes, &result)
	return result
}

func Test_apply(t *testing.T) {
	t.Run("#4076: min without max should not panic", func(t *testing.T) {
		t.Log("Tests regression of https://github.com/nuts-foundation/nuts-node/issues/4076")
		// Create test VCs
		vc1 := testVC("did:example:1")
		vc2 := testVC("did:example:2")
		vc3 := testVC("did:example:3")

		// Create submission requirement with min but no max
		submissionRequirement := SubmissionRequirement{
			Name: "test",
			Rule: "pick",
			Min:  to.Ptr(2),
			Max:  nil, // Max is nil, which should not cause a panic
		}

		// Convert VCs to selectableVC
		list := []selectableVC{
			selectableVC(vc1),
			selectableVC(vc2),
			selectableVC(vc3),
		}

		// This should not panic
		result, err := apply(list, submissionRequirement)

		// Should succeed and return all VCs that meet the min requirement
		require.NoError(t, err)
		assert.Len(t, result, 3) // Should return all 3 VCs since no max is specified
	})

	t.Run("max with min should respect max limit", func(t *testing.T) {
		// Create test VCs
		vc1 := testVC("did:example:1")
		vc2 := testVC("did:example:2")
		vc3 := testVC("did:example:3")

		// Create submission requirement with min and max
		submissionRequirement := SubmissionRequirement{
			Name: "test",
			Rule: "pick",
			Min:  to.Ptr(1),
			Max:  to.Ptr(2),
		}

		// Convert VCs to selectableVC
		list := []selectableVC{
			selectableVC(vc1),
			selectableVC(vc2),
			selectableVC(vc3),
		}

		// Apply the submission requirement
		result, err := apply(list, submissionRequirement)

		// Should succeed and return only 2 VCs (respecting max)
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("only max should work without min", func(t *testing.T) {
		// Create test VCs
		vc1 := testVC("did:example:1")
		vc2 := testVC("did:example:2")
		vc3 := testVC("did:example:3")

		// Create submission requirement with only max
		submissionRequirement := SubmissionRequirement{
			Name: "test",
			Rule: "pick",
			Min:  nil,
			Max:  to.Ptr(2),
		}

		// Convert VCs to selectableVC
		list := []selectableVC{
			selectableVC(vc1),
			selectableVC(vc2),
			selectableVC(vc3),
		}

		// Apply the submission requirement
		result, err := apply(list, submissionRequirement)

		// Should succeed and return only 2 VCs (respecting max)
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})
}
