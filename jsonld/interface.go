/*
 * Nuts node
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

package jsonld

import (
	"github.com/piprate/json-gold/ld"
)

// ContextManager manages the different JSON-LD contexts. It helps in using the same loaded contexts over different engines.
type ContextManager interface {
	// DocumentLoader returns the JSON-LD documentLoader
	DocumentLoader() ld.DocumentLoader
	// Reader returns a DocumentReader loaded with the correct JSON-LD contexts
	Reader() DocumentReader
}
