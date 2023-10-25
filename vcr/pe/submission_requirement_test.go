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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_match(t *testing.T) {
	t.Run("error - submission requirement with both from and from_nested", func(t *testing.T) {
		submissionRequirement := SubmissionRequirement{
			Name:       "test",
			From:       "A",
			FromNested: []*SubmissionRequirement{{Name: "test"}},
		}
		availableGroups := map[string]GroupCandidates{}
		_, err := submissionRequirement.match(availableGroups)
		require.Error(t, err)
		assert.EqualError(t, err, "submission requirement (test) contains both 'from' and 'from_nested'")
	})
}
