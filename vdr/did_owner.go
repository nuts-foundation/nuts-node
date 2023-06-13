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

package vdr

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
	"sync"
)

var _ types.DocumentOwner = (*cachingDocumentOwner)(nil)
var _ types.DocumentOwner = (*privateKeyDocumentOwner)(nil)

// cachingDocumentOwner is a types.DocumentOwner that caches the result, minimizing expensive lookups.
// It assumes:
//   - Positive matches never change until restart (would indicate a DID deactivation, and it being used afterwards).
//   - Negative matches never change until restart (would indicate an attacker trying DIDs, or a bug/misconfiguration).
//
// Before calling the more expensive, underlying types.DocumentOwner, it checks whether the DID actually exists.
type cachingDocumentOwner struct {
	underlying   types.DocumentOwner
	ownedDIDs    *sync.Map
	notOwnedDIDs *sync.Map
	docResolver  types.DocResolver
}

func newCachingDocumentOwner(underlying types.DocumentOwner, docResolver types.DocResolver) *cachingDocumentOwner {
	return &cachingDocumentOwner{
		docResolver:  docResolver,
		underlying:   underlying,
		ownedDIDs:    new(sync.Map),
		notOwnedDIDs: new(sync.Map),
	}
}

func (t *cachingDocumentOwner) IsOwner(ctx context.Context, id did.DID) (bool, error) {
	// Check if the DID is in the negative matches
	isAsString := id.String()
	_, isNotATenant := t.notOwnedDIDs.Load(isAsString)
	if isNotATenant {
		return false, nil
	}

	// Check if the DID is in the positive matches
	_, isATenant := t.ownedDIDs.Load(isAsString)
	if isATenant {
		return true, nil
	}

	// First perform a cheap DID existence check (subsequent checks are more expensive),
	// without caching it as negative match (would allow unbound number of negative matches).
	_, _, err := t.docResolver.Resolve(id, nil)
	if didservice.IsFunctionalResolveError(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("unable to check ownership of DID: %w", err)
	}

	result, err := t.underlying.IsOwner(ctx, id)
	if err != nil {
		return false, err
	}

	// Cache result for future use
	if result {
		t.ownedDIDs.Store(isAsString, true)
	} else {
		t.notOwnedDIDs.Store(isAsString, true)
	}

	return result, nil
}

// privateKeyDocumentOwner checks if the DID is managed by the local node by checking if there are private keys of the DID in the node's key store.
// It does not check whether the DID is active or not, or whether the private keys are still (if ever) were registered on the DID document.
type privateKeyDocumentOwner struct {
	keyResolver crypto.KeyResolver
}

func (p privateKeyDocumentOwner) IsOwner(ctx context.Context, id did.DID) (bool, error) {
	idAsString := id.String()
	keyList := p.keyResolver.List(ctx)
	for _, key := range keyList {
		// Assume format <did>#<keyID>
		idx := strings.Index(key, "#")
		if idx == -1 {
			// Not a valid key ID
			continue
		}
		ownerDID := key[:idx]
		if idAsString == ownerDID {
			return true, nil
		}
	}
	return false, nil
}
