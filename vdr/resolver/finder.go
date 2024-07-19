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

package resolver

import (
	"github.com/nuts-foundation/go-did/did"
	"strings"
	"time"
)

// DocFinder is the interface that groups all methods for finding DID documents based on search conditions
type DocFinder interface {
	Find(...Predicate) ([]did.Document, error)
}

// Predicate is an interface for abstracting search options on DID documents
type Predicate interface {
	// Match returns true if the given DID Document passes the predicate condition
	Match(did.Document, DocumentMetadata) bool
}

// DocIterator is the function type for iterating over the all current DID Documents in the store
type DocIterator func(doc did.Document, metadata DocumentMetadata) error

// ByServiceType returns a predicate that matches on service type
// it only matches on DID Documents with a concrete endpoint (not starting with "did")
func ByServiceType(serviceType string) Predicate {
	return servicePredicate{serviceType: serviceType}
}

type servicePredicate struct {
	serviceType string
}

func (s servicePredicate) Match(document did.Document, _ DocumentMetadata) bool {
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
func ValidAt(at time.Time) Predicate {
	return validAtPredicate{validAt: at}
}

type validAtPredicate struct {
	validAt time.Time
}

func (v validAtPredicate) Match(_ did.Document, metadata DocumentMetadata) bool {
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
func IsActive() Predicate {
	return deactivatedPredicate{deactivated: false}
}

type deactivatedPredicate struct {
	deactivated bool
}

func (d deactivatedPredicate) Match(_ did.Document, metadata DocumentMetadata) bool {
	return d.deactivated == metadata.Deactivated
}
