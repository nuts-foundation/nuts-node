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
	"encoding/json"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/piprate/json-gold/ld"
)

// JSONLdBase is the base URL used for IRIs that are unknown when expanding a JSON-LD document.
const JSONLdBase = ""

type transformer struct {
	documentLoader ld.DocumentLoader
}

func (t transformer) FromVC(credential vc.VerifiableCredential) (Document, error) {
	asJSON, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	return t.FromBytes(asJSON)
}

func (t transformer) FromBytes(asJSON []byte) (Document, error) {
	compact := make(map[string]interface{})
	if err := json.Unmarshal(asJSON, &compact); err != nil {
		return nil, err
	}

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions(JSONLdBase)
	options.DocumentLoader = t.documentLoader

	return processor.Expand(compact, options)
}
