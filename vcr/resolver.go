/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
)

type nameResolver struct {
	vcr *vcr
}

func (c *vcr) NameResolver() NameResolver {
	return nameResolver{vcr: c}
}

func (n nameResolver) Resolve(ID did.DID) (string, string, error) {
	q, err := n.vcr.Registry().QueryFor(concept.OrganizationConcept)
	if err != nil {
		return "", "", err
	}

	q.AddClause(concept.Eq(concept.SubjectField, ID.String()))

	vcs, err := n.vcr.Search(q)
	if err != nil {
		return "", "", err
	}

	if len(vcs) == 0 {
		return "", "", ErrNotFound
	}

	// multiple valids, use first one
	c, err := n.vcr.Registry().Transform(concept.OrganizationConcept, vcs[0])
	if err != nil {
		return "", "", err
	}

	name := ""
	city := ""
	ok := false

	if name, ok = c.GetValue(concept.OrganizationName).(string); !ok {
		return "", "", ErrNotFound
	}
	if city, ok = c.GetValue(concept.OrganizationCity).(string); !ok {
		return "", "", ErrNotFound
	}

	return name, city, nil
}
