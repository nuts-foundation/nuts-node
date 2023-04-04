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
 *
 */

package transport

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

// Resolve returns the auto-resolved node DID, or an empty DID if none could be found.
func AutoResolveNodeDID(ctx context.Context, keyResolver crypto.KeyResolver, docFinder types.DocFinder) (*did.DID, error) {
	documents, err := docFinder.Find(didservice.IsActive(), didservice.ValidAt(time.Now()), didservice.ByServiceType(NutsCommServiceType))
	if err != nil {
		return &did.DID{}, err
	}

	privateKeyIDs := keyResolver.List(ctx)

	// Intersect DID documents with an absolute NutsComm endpoint (which vendors must have) with the private keys present in the local keystore.
	for _, document := range documents {
		for _, capabilityInvocation := range document.CapabilityInvocation {
			// While multiple DID documents may match, always take the first. That way it will always take the same DID document after a restart.
			if contains(privateKeyIDs, capabilityInvocation.ID.String()) {
				return &document.ID, nil
			}
		}
	}

	return &did.DID{}, nil
}

func contains(haystack []string, needle string) bool {
	for _, curr := range haystack {
		if curr == needle {
			return true
		}
	}
	return false
}
