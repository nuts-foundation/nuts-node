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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubmissionRequirement_Groups(t *testing.T) {
	t.Run("group from a single requirement", func(t *testing.T) {
		requirement := SubmissionRequirement{
			From: "A",
		}

		groups := requirement.Groups()

		assert.Equal(t, []string{"A"}, groups)
	})
	t.Run("groups from nested requirements", func(t *testing.T) {
		requirement := SubmissionRequirement{
			From: "A",
			FromNested: []*SubmissionRequirement{
				{From: "B"},
			},
		}

		groups := requirement.Groups()

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

		groups := requirement.Groups()

		assert.Equal(t, []string{"A", "B"}, groups)
	})
}
