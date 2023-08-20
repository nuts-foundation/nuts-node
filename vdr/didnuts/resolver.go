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

package didnuts

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const maxControllerDepth = 5

// ErrNestedDocumentsTooDeep is returned when a DID Document contains a multiple services with the same type
var ErrNestedDocumentsTooDeep = errors.New("DID Document controller structure has too many indirections")

// Resolver implements the DIDResolver interface for resolving did:nuts documents.
type Resolver struct {
	Store didstore.Store
}

func (d Resolver) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	if metadata != nil && metadata.AllowDeactivated {
		// No need to check whether controllers are active if we allow deactivated documents
		return d.Store.Resolve(id, metadata)
	}
	return resolve(d.Store, id, metadata, 0)
}

func resolve(resolver types.DIDResolver, id did.DID, metadata *types.ResolveMetadata, depth int) (*did.Document, *types.DocumentMetadata, error) {
	if depth >= maxControllerDepth {
		return nil, nil, ErrNestedDocumentsTooDeep
	}

	doc, meta, err := resolver.Resolve(id, metadata)
	if err != nil {
		return nil, nil, err
	}

	// has the doc controllers, should we check for controller deactivation?
	if len(doc.Controller) > 0 && (metadata == nil || !metadata.AllowDeactivated) {
		// also check if the controller is not deactivated
		// since ResolveControllers calls Resolve and propagates the metadata
		controllers, err := resolveControllers(resolver, *doc, metadata, depth+1)
		if err != nil {
			return nil, nil, err
		}
		// doc should have controllers, but no results, so they are not active, return error:
		if len(controllers) == 0 {
			return nil, nil, types.ErrNoActiveController
		}
	}

	return doc, meta, nil
}

// ResolveControllers finds the DID Document controllers
func ResolveControllers(resolver types.DIDResolver, doc did.Document, metadata *types.ResolveMetadata) ([]did.Document, error) {
	return resolveControllers(resolver, doc, metadata, 0)
}

func resolveControllers(resolver types.DIDResolver, doc did.Document, metadata *types.ResolveMetadata, depth int) ([]did.Document, error) {
	var leaves []did.Document
	var refsToResolve []did.DID

	if len(doc.Controller) == 0 && len(doc.CapabilityInvocation) > 0 {
		// no controller -> doc is its own controller
		leaves = append(leaves, doc)
	} else {
		for _, ctrlDID := range doc.Controller {
			if doc.ID.Equals(ctrlDID) {
				if len(doc.CapabilityInvocation) > 0 {
					// doc is its own controller
					leaves = append(leaves, doc)
				}
			} else {
				// add did to be resolved later
				refsToResolve = append(refsToResolve, ctrlDID)
			}
		}
	}

	// resolve all unresolved doc
	for _, ref := range refsToResolve {
		node, _, err := resolve(resolver, ref, metadata, depth)
		if errors.Is(err, types.ErrDeactivated) || errors.Is(err, types.ErrNoActiveController) || errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrDIDMethodNotSupported) {
			continue
		}
		if errors.Is(err, ErrNestedDocumentsTooDeep) {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("unable to resolve controller ref: %w", err)
		}
		leaves = append(leaves, *node)
	}

	// filter deactivated
	j := 0
	for _, leaf := range leaves {
		if !didservice.IsDeactivated(leaf) {
			leaves[j] = leaf
			j++
		}
	}

	return leaves[:j], nil
}
