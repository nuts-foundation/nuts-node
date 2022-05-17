/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package vcr

// ModuleName holds the name of the engine
const ModuleName = "VCR"

// Config holds the config for the vcr engine
type Config struct {
	// strictMode is a copy from the core server config
	strictMode bool
	// datadir holds the location the VCR files are stored
	datadir string
}

// DefaultConfig returns a fresh Config filled with default values
func DefaultConfig() Config {
	return Config{}
}
