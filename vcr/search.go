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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/sirupsen/logrus"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
)

const (
	// Exact is the SearchTerm type that requires a search path to result in an exact match
	Exact = "exact"
	// NotNil is the SearchTerm type that requires a search path to result in a non nil value
	NotNil = "notNil"
	// Prefix is the SearchTerm type that does a prefix match
	Prefix = "prefix"
)

// SearchTerm is part of a JSON-LD query. Multiple terms are combined in an 'AND' manner.
type SearchTerm struct {
	IRIPath []string
	Value   interface{}
	Type    string
}

func (c *vcr) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
	query := leia.Query{}
	var VCs = make([]vc.VerifiableCredential, 0)

	for _, searchTerm := range searchTerms {
		var scalar leia.Scalar
		var err error
		if searchTerm.Type != NotNil {
			scalar, err = leia.ParseScalar(searchTerm.Value)
			if err != nil {
				return nil, fmt.Errorf("value type (value=%v, type=%s) not supported at %s", searchTerm.Value, reflect.TypeOf(searchTerm.Value), strings.Join(searchTerm.IRIPath, ", "))
			}
		}

		switch searchTerm.Type {
		case NotNil:
			query = query.And(leia.NotNil(leia.NewIRIPath(searchTerm.IRIPath...)))
		case Prefix:
			query = query.And(leia.Prefix(leia.NewIRIPath(searchTerm.IRIPath...), scalar))
		default:
			fallthrough
		case Exact:
			query = query.And(leia.Eq(leia.NewIRIPath(searchTerm.IRIPath...), scalar))
		}
	}

	docs, err := c.credentialCollection().Find(ctx, query)
	if err != nil {
		return nil, err
	}
	verifyErrors := make(map[string]int, 0)
	for _, doc := range docs {
		foundCredential := vc.VerifiableCredential{}
		err = json.Unmarshal(doc, &foundCredential)
		if err != nil {
			return nil, fmt.Errorf("unable to parse credential from db: %w", err)
		}

		if err = c.verifier.Verify(foundCredential, allowUntrusted, false, resolveTime); err == nil {
			VCs = append(VCs, foundCredential)
		} else {
			log.Logger().
				WithError(err).
				WithField(core.LogFieldCredentialID, foundCredential.ID).
				Trace("Encountered invalid VC, omitting from search results.")
			verifyErrors[err.Error()]++
		}
	}

	// Print debug log if we found invalid credentials, make a distinction between different errors
	if len(verifyErrors) > 0 && log.Logger().Level >= logrus.DebugLevel {
		log.Logger().Debug(formatFilteredVCsLogMessage(verifyErrors))
	}

	return VCs, nil
}

func formatFilteredVCsLogMessage(verifyErrors map[string]int) string {
	parts := make([]string, 0, len(verifyErrors))
	numFiltered := 0
	for err, count := range verifyErrors {
		parts = append(parts, fmt.Sprintf("'%s' (%d times)", err, count))
		sort.Strings(parts)
		numFiltered += count
	}
	msg := fmt.Sprintf("Filtered %d invalid VCs from search results (more info on TRACE): %s", numFiltered, strings.Join(parts, ", "))
	return msg
}
