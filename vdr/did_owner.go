package vdr

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
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
type cachingDocumentOwner struct {
	underlying   types.DocumentOwner
	ownedDIDs    *sync.Map
	notOwnedDIDs *sync.Map
}

func newCachingDocumentOwner(underlying types.DocumentOwner) *cachingDocumentOwner {
	return &cachingDocumentOwner{
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
