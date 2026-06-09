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

package log

import "mime"

// IsLoggableContentType returns true for content types whose body is safe and useful to log as text.
// It is the single source of truth for both client- and server-side HTTP body logging.
func IsLoggableContentType(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/json",
		"application/did+json",
		"application/vc+json",
		"application/x-www-form-urlencoded":
		return true
	}
	return false
}
