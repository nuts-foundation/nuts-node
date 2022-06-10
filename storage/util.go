/*
 * Copyright (C) 2022 Nuts community
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

package storage

import (
	"fmt"
	"time"
)

// MarshallingDuration wraps time.Duration so it can be unmarshalled from YAML
type MarshallingDuration time.Duration

func (d MarshallingDuration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText parses a string representation of time.Duration into time.Duration
func (d *MarshallingDuration) UnmarshalText(text []byte) error {
	value, err := time.ParseDuration(string(text))
	*d = MarshallingDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration '%s': %w", string(text), err)
	}
	return nil
}
