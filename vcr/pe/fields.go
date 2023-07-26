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

// Field describes a field in a presentation submission, predicate feature is not implemented
type Field struct {
	Id             *string  `json:"id,omitempty"`
	Optional       *bool    `json:"optional,omitempty"`
	Path           []string `json:"path"`
	Purpose        *string  `json:"purpose,omitempty"`
	Name           *string  `json:"name,omitempty"`
	IntentToRetain *bool    `json:"intent_to_retain,omitempty"`
	Filter         *Filter  `json:"filter,omitempty"`
}

// Filter is a JSON Schema descriptor
type Filter struct {
	// Type is the type of field: string, number, boolean, array, object
	Type string `json:"type"`
	// Const is a constant value to match, currently only strings are supported
	Const *string `json:"const,omitempty"`
	// Enum is a list of values to match
	Enum *[]string `json:"enum,omitempty"`
	// Pattern is a pattern to match according to ECMA-262, section 21.2.1
	Pattern *string `json:"pattern,omitempty"`
}
