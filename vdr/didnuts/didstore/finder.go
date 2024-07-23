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

package didstore

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// Finder is a helper that implements the DocFinder interface
type Finder struct {
	Store Store
}

func (f Finder) Find(predicate ...resolver.Predicate) ([]did.Document, error) {
	matches := make([]did.Document, 0)

	err := f.Store.Iterate(func(doc did.Document, metadata resolver.DocumentMetadata) error {
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
