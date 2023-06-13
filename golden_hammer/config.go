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

package golden_hammer

import "time"

// Config contains the configuration for the module.
type Config struct {
	// Enabled indicates whether the module is enabled.
	Enabled bool `koanf:"enabled"`
	// Interval is the interval at which the module should apply its fixes.
	Interval time.Duration `koanf:"interval"`
}

// DefaultConfig returns the default configuration for the module.
func DefaultConfig() *Config {
	return &Config{
		Enabled:  true,
		Interval: 10 * time.Minute,
	}
}
