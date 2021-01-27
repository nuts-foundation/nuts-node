/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package core

import "time"

// Period is a convenience type for valid from and valid to dateTime.
type Period struct {
	ValidFrom time.Time `json:"validFrom"`
	ValidTo *time.Time  `json:"validTo,omitempty"`
}

// Contains checks if the given time falls within this period
func (p Period) Contains(when time.Time) bool {
	if when.Before(p.ValidFrom) {
		return false
	}

	return !(p.ValidTo != nil && when.After(*p.ValidTo))
}

// RFC3339Time is a time that marshals as RFC3337
type RFC3339Time struct {
	time.Time
}

func (j RFC3339Time) MarshalText() ([]byte, error) {
	return []byte(j.Format(time.RFC3339)), nil
}

func (j *RFC3339Time) UnmarshalJSON(bytes []byte) error {
	t, err := time.Parse(time.RFC3339, string(bytes))
	if err != nil {
		return err
	}
	*j = RFC3339Time{t}

	return nil
}
