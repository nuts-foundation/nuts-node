/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

// Period is a convenience type for a dateTime range.
type Period struct {
	Begin time.Time  `json:"begin"`
	End   *time.Time `json:"end,omitempty"`
}

// Contains checks if the given time falls within this period. The bounds are inclusive.
func (p Period) Contains(when time.Time) bool {
	if when.Before(p.Begin) {
		return false
	}

	return !(p.End != nil && when.After(*p.End))
}

// RFC3339Time is a time that marshals as RFC3339
type RFC3339Time struct {
	time.Time
}

// MarshalText marshals the time in RFC3339 format
func (j RFC3339Time) MarshalText() ([]byte, error) {
	return []byte(j.Format(time.RFC3339)), nil
}

// UnmarshalJSON parses the time string using RFC3339 format
func (j *RFC3339Time) UnmarshalJSON(bytes []byte) error {
	t, err := time.Parse(time.RFC3339, string(bytes))
	if err != nil {
		return err
	}
	*j = RFC3339Time{t}

	return nil
}
