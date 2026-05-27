/*
 * Copyright (C) 2026 Nuts community
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

package holder

import (
	"time"

	"github.com/nuts-foundation/go-did/did"
)

// SearchOption is a filter that narrows the results returned by Wallet.Search. Multiple options
// are combined with logical AND.
type SearchOption func(*searchQuery)

// searchQuery holds the resolved filter state for a single Wallet.Search call.
type searchQuery struct {
	holderDID              *did.DID
	excludeCredentialTypes []string
	expiresAt              *time.Time
}

// HolderDID restricts results to credentials held by the given DID.
func HolderDID(d did.DID) SearchOption {
	return func(q *searchQuery) { q.holderDID = &d }
}

// ExcludeCredentialTypes drops credentials whose type matches any of the given values. Credentials
// without a stored type (NULL) are kept.
func ExcludeCredentialTypes(types ...string) SearchOption {
	return func(q *searchQuery) {
		if len(types) == 0 {
			return
		}
		q.excludeCredentialTypes = append(q.excludeCredentialTypes, types...)
	}
}

// ExpiresAt restricts results to credentials whose expirationDate is set and falls at or before t.
// Credentials without an expirationDate are not returned. Callers compute t from their own clock
// so this is a fixed threshold from the wallet's perspective.
func ExpiresAt(t time.Time) SearchOption {
	return func(q *searchQuery) { q.expiresAt = &t }
}

// buildSearchQuery applies the options to a fresh searchQuery and returns it.
func buildSearchQuery(opts []SearchOption) searchQuery {
	var q searchQuery
	for _, opt := range opts {
		opt(&q)
	}
	return q
}
