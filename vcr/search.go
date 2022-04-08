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

const (
	Prefix = "prefix"
	Exact  = "exact"
	NotNil = "notNil"
)

type SearchTerm struct {
	IRIPath []string
	Value   interface{}
	Type    string
}

func (c *vcr) Expand(credential vc.VerifiableCredential) ([]interface{}, error) {
	jsonLD, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	return signature.LDUtil{LDDocumentLoader: c.contextLoader}.Expand(jsonLD)
}

func (c *vcr) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
	query := leia.Query{}
	var VCs = make([]vc.VerifiableCredential, 0)

	for _, searchTerm := range searchTerms {
		scalar, err := leia.ParseScalar(searchTerm.Value)
		if err != nil {
			return nil, fmt.Errorf("value type not supported at %s", strings.Join(searchTerm.IRIPath, "."))
		}

		switch searchTerm.Type {
		case Exact:
			query = query.And(leia.Eq(leia.NewIRIPath(searchTerm.IRIPath...), scalar))
		case NotNil:
			query = query.And(leia.NotNil(leia.NewIRIPath(searchTerm.IRIPath...)))
		default:
			query = query.And(leia.Prefix(leia.NewIRIPath(searchTerm.IRIPath...), scalar))
		}

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
