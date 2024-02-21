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
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Validate returns an error if the contents of the Entry violate the spec.
func (e Entry) Validate() error {
	// 'id' MUST NOT be the URL for the status list
	if e.ID == e.StatusListCredential {
		return errors.New("StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
	}

	if e.Type != EntryType {
		return errors.New("StatusList2021Entry.type must be StatusList2021Entry")
	}

	// StatusPurpose must contain a purpose
	if e.StatusPurpose == "" {
		return errors.New("StatusList2021Entry.statusPurpose is required")
	}

	// statusListIndex must be a non-negative number
	if n, err := strconv.Atoi(e.StatusListIndex); err != nil || n < 0 {
		return errors.New("invalid StatusList2021Entry.statusListIndex")
	}

	// 'statusListCredential' must be a URL
	if _, err := url.ParseRequestURI(e.StatusListCredential); err != nil {
		return fmt.Errorf("parse StatusList2021Entry.statusListCredential URL: %w", err)
	}

	return nil
}
