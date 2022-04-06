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

package vcr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

type SearchTerm struct {
	IRIPath []string
	Value   interface{}
}

func (c *vcr) Expand(credential vc.VerifiableCredential) ([]interface{}, error) {
	jsonLD, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	return signature.LDUtil{LDDocumentLoader: c.contextLoader}.Expand(jsonLD)
}

func (c *vcr) ExpandAndConvert(credential vc.VerifiableCredential) ([]SearchTerm, error) {
	jsonLD, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	expanded, err := signature.LDUtil{LDDocumentLoader: c.contextLoader}.Expand(jsonLD)
	if err != nil {
		return nil, err
	}
	return flatten(expanded, nil), nil
}

func flatten(expanded interface{}, currentPath []string) []SearchTerm {
	switch t := expanded.(type) {
	case []interface{}:
		return flattenSlice(t, currentPath)
	case map[string]interface{}:
		return flattenMap(t, currentPath)
	}

	return nil
}

func flattenSlice(expanded []interface{}, currentPath []string) []SearchTerm {
	result := make([]SearchTerm, 0)

	for _, sub := range expanded {
		result = append(result, flatten(sub, currentPath)...)
	}

	return result
}

func flattenMap(expanded map[string]interface{}, currentPath []string) []SearchTerm {
	// JSON-LD in expanded form either has @value, @id, @list or objects

	results := make([]SearchTerm, 0)

	for k, v := range expanded {
		switch k {
		case "@id":
			fallthrough
		case "@value":
			results = append(results, SearchTerm{
				IRIPath: currentPath,
				Value:   v,
			})
		case "@list":
			// TODO: not supported...
		default:
			results = append(results, flatten(v, append(currentPath, k))...)
		}
	}

	return results
}

func (c *vcr) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
	query := leia.Query{}
	var VCs = make([]vc.VerifiableCredential, 0)

	for _, searchTerm := range searchTerms {
		scalar, err := leia.ParseScalar(searchTerm.Value)
		if err != nil {
			return nil, fmt.Errorf("value type not supported at %s", strings.Join(searchTerm.IRIPath, "."))
		}

		query = query.And(leia.Prefix(leia.NewIRIPath(searchTerm.IRIPath...), scalar))
	}

	docs, err := c.credentialCollection().Find(ctx, query)
	if err != nil {
		return nil, err
	}
	for _, doc := range docs {
		foundCredential := vc.VerifiableCredential{}
		err = json.Unmarshal(doc, &foundCredential)
		if err != nil {
			return nil, fmt.Errorf("unable to parse credential from db: %w", err)
		}

		if err = c.Validate(foundCredential, allowUntrusted, false, resolveTime); err == nil {
			VCs = append(VCs, foundCredential)
		}
	}

	return nil, nil
}
