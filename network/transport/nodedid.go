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
	"sync"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// NodeDIDResolver defines an interface for types that resolve the local node's DID, which is used to identify the node on the network.
type NodeDIDResolver interface {
	// Resolve tries to resolve the node DID. If it's absent, an empty DID is returned. In any other non-successful case an error is returned.
	Resolve() (did.DID, error)
}

// FixedNodeDIDResolver is a NodeDIDResolver that returns a preset DID.
type FixedNodeDIDResolver struct {
	NodeDID did.DID
}

// Resolve returns the fixed-set node DID.
func (f FixedNodeDIDResolver) Resolve() (did.DID, error) {
	return f.NodeDID, nil
}

// NewAutoNodeDIDResolver creates a new node DID resolver that tried to look it up by matching DID documents with a NutsComm endpoint set and the private key of the local node.
func NewAutoNodeDIDResolver(keyResolver crypto.KeyResolver, docFinder types.DocFinder) NodeDIDResolver {
	return &autoNodeDIDResolver{
		keyResolver: keyResolver,
		docFinder:   docFinder,
		mux:         &sync.Mutex{},
	}
}

type autoNodeDIDResolver struct {
	keyResolver crypto.KeyResolver
	docFinder   types.DocFinder
	mux         *sync.Mutex
	resolvedDID did.DID
}

// Resolve returns the auto-resolved node DID, or an empty DID if none could be found.
func (a *autoNodeDIDResolver) Resolve() (did.DID, error) {
	a.mux.Lock()
	defer a.mux.Unlock()
	if !a.resolvedDID.Empty() {
		result := a.resolvedDID
		return result, nil
	}

	documents, err := a.docFinder.Find(didservice.IsActive(), didservice.ValidAt(time.Now()), didservice.ByServiceType(NutsCommServiceType))
	if err != nil {
		return did.DID{}, err
	}

	privateKeyIDs := a.keyResolver.List()

	// Intersect DID documents with an absolute NutsComm endpoint (which vendors must have) with the private keys present in the local keystore.
outer:
	for _, document := range documents {
		for _, capabilityInvocation := range document.CapabilityInvocation {
			// While multiple DID documents may match, always take the first. That way it will always take the same DID document after a restart.
			if contains(privateKeyIDs, capabilityInvocation.ID.String()) {
				a.resolvedDID = document.ID
				break outer
			}
		}
	}

	return a.resolvedDID, nil
}

func contains(haystack []string, needle string) bool {
	for _, curr := range haystack {
		if curr == needle {
			return true
		}
	}
	return false
}
