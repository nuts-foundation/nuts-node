package vcr

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"strings"
	"sync"
)

var _ TenantRegistry = (*cachedTenantRegistry)(nil)

// cachedTenantRegistry keeps track of which DIDs are managed by the local node.
// A tenant is a DID with key material present in the node's key store. The check is easy enough, but the data structure
// adds caching to avoid having to check the key store for every request.
// It assumes:
//   - Positive matches never change (would indicate a DID deactivation, and it being used afterwards).
//   - Negative matches never change (would indicate an attacker trying DIDs, or a bug/misconfiguration) until restart.
//
// Since it does some assumptions it should not be used as authorization mechanism,
// since it does not unmark as tenant when a DID is deactivated.
type cachedTenantRegistry struct {
	keyResolver     crypto.KeyResolver
	tenantsList     *sync.Map
	negativeMatches *sync.Map
	updateLock      *sync.Mutex
}

func newCachedTenantsRegistry(keyResolver crypto.KeyResolver) *cachedTenantRegistry {
	return &cachedTenantRegistry{
		keyResolver:     keyResolver,
		updateLock:      &sync.Mutex{},
		tenantsList:     new(sync.Map),
		negativeMatches: new(sync.Map),
	}
}

func (t *cachedTenantRegistry) IsProbableTenant(ctx context.Context, id did.DID) (bool, error) {
	// Check if the DID is in the negative matches
	isAsString := id.String()
	_, isNotATenant := t.negativeMatches.Load(isAsString)
	if isNotATenant {
		return false, nil
	}

	// Check if the DID is in the positive matches
	_, isATenant := t.tenantsList.Load(isAsString)
	if isATenant {
		return true, nil
	}

	// We don't know if it's a tenant, refresh list
	keyList := t.keyResolver.List(ctx)
	for _, key := range keyList {
		// Assume format <did>#<keyID>
		idx := strings.Index(key, "#")
		if idx == -1 {
			// Not a valid key ID
			continue
		}
		tenantDID := key[:idx]
		if isAsString == tenantDID {
			// Positive match
			isATenant = true
		}
		t.tenantsList.Store(tenantDID, true)
	}

	// If really not a tenant, update negative matches list
	if !isATenant {
		t.negativeMatches.Store(isAsString, true)
	}

	return isATenant, nil
}
