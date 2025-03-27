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
	"github.com/nuts-foundation/nuts-node/json"

	"github.com/piprate/json-gold/ld"
)

// JSONLdBase is the base URL used for IRIs that are unknown when expanding a JSON-LD document.
const JSONLdBase = ""

// Reader adds Document reader functions for a JSON-LD context.
type Reader struct {
	// DocumentLoader the document loader that resolves JSON-LD context urls
	DocumentLoader ld.DocumentLoader
	// AllowUndefinedProperties specifies whether the reader should return an error when it occurs a property that is not defined in the JSON-LD context.
	AllowUndefinedProperties bool
}

// Read transforms a struct to a Document (expanded JSON-LD)
func (r Reader) Read(source interface{}) (Document, error) {
	asJSON, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}

	return r.ReadBytes(asJSON)
}

// ReadBytes transforms a JSON-LD string to a Document (expanded JSON-LD)
func (r Reader) ReadBytes(asJSON []byte) (Document, error) {
	compact := make(map[string]interface{})
	if err := json.Unmarshal(asJSON, &compact); err != nil {
		return nil, err
	}

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions(JSONLdBase)
	options.SafeMode = !r.AllowUndefinedProperties
	options.DocumentLoader = r.DocumentLoader

	return processor.Expand(compact, options)
}
