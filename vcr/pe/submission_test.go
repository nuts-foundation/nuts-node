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

func TestParsePresentationSubmission(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		submission, err := ParsePresentationSubmission([]byte(`{"id": "1", "definition_id":"1", "descriptor_map": []}`))
		require.NoError(t, err)
		assert.Equal(t, "1", submission.Id)
	})
	t.Run("missing id", func(t *testing.T) {
		_, err := ParsePresentationSubmission([]byte(`{"definition_id":"1", "descriptor_map": []}`))
		assert.ErrorContains(t, err, `missing properties: "id"`)
	})
}
