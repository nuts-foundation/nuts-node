/*
 * Copyright (C) 2024 Nuts community
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

package statuslist2021

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEntry_Validate(t *testing.T) {
	makeValidCSEntry := func() Entry {
		return Entry{
			ID:                   "https://example-com/credentials/status/3#94567",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "94567",
			StatusListCredential: "https://example-com/credentials/status/3",
		}
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, makeValidCSEntry().Validate())
	})
	t.Run("error - id == statusListCredential", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.ID = entry.StatusListCredential
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
	})
	t.Run("error - incorrect type", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.Type = "Wrong Type"
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.type must be StatusList2021Entry")
	})
	t.Run("error - missing statusPurpose", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusPurpose = ""
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.statusPurpose is required")
	})
	t.Run("error - statusListIndex is negative", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListIndex = "-1"
		err := entry.Validate()
		assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
	})
	t.Run("error - statusListIndex is not a number", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListIndex = "one"
		err := entry.Validate()
		assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
	})
	t.Run("error - statusListCredential is not a valid URL", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListCredential = "not a URL"
		err := entry.Validate()
		assert.EqualError(t, err, "parse StatusList2021Entry.statusListCredential URL: parse \"not a URL\": invalid URI for request")
	})
}
