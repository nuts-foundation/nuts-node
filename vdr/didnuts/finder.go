/*
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
 */

package didnuts

import (
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/store"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ByServiceType returns a predicate that matches on service type
// it only matches on DID Documents with a concrete endpoint (not starting with "did")
func ByServiceType(serviceType string) types.Predicate {
	return servicePredicate{serviceType: serviceType}
}

type servicePredicate struct {
	serviceType string
}

func (s servicePredicate) Match(document did.Document, _ types.DocumentMetadata) bool {
	for _, service := range document.Service {
		if service.Type == s.serviceType {
			var nutsCommStr string
			if err := service.UnmarshalServiceEndpoint(&nutsCommStr); err == nil && !strings.HasPrefix(nutsCommStr, "did") {
				return true
			}
		}
	}
	return false
}

// ValidAt returns a predicate that matches on validity period.
func ValidAt(at time.Time) types.Predicate {
	return validAtPredicate{validAt: at}
}

type validAtPredicate struct {
	validAt time.Time
}

func (v validAtPredicate) Match(_ did.Document, metadata types.DocumentMetadata) bool {
	if v.validAt.Before(metadata.Created) {
		return false
	}

	if metadata.Updated != nil {
		if metadata.Updated.After(v.validAt) {
			return false
		}
	}

	return true
}

// IsActive returns a predicate that matches DID Documents that are not deactivated.
func IsActive() types.Predicate {
	return deactivatedPredicate{deactivated: false}
}

type deactivatedPredicate struct {
	deactivated bool
}

func (d deactivatedPredicate) Match(_ did.Document, metadata types.DocumentMetadata) bool {
	return d.deactivated == metadata.Deactivated
}

// Finder is a helper that implements the DocFinder interface
type Finder struct {
	Store store.Store
}

func (f Finder) Find(predicate ...types.Predicate) ([]did.Document, error) {
	matches := make([]did.Document, 0)

	err := f.Store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		for _, p := range predicate {
			if !p.Match(doc, metadata) {
				return nil
			}
		}
		matches = append(matches, doc)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return matches, err
}
