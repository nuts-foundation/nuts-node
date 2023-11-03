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

package util

import ssi "github.com/nuts-foundation/go-did"

// LDContextToString converts a JSON-LD context to a string, if it's a string or a ssi.URI
// If it's not a string or ssi.URI, it will return an empty string.
func LDContextToString(context interface{}) string {
	var result string
	switch ctx := context.(type) {
	case ssi.URI:
		result = ctx.String()
	case string:
		result = ctx
	}
	return result
}
