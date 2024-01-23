/*
 * Copyright (C) 2024 Nuts community
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
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// NewManager creates a new Manager instance.
func NewManager(creator management.DocCreator, owner management.DocumentOwner) *Manager {
	return &Manager{
		Creator:       creator,
		DocumentOwner: owner,
	}
}

var _ management.DocumentManager = (*Manager)(nil)

type Manager struct {
	Creator       management.DocCreator
	DocumentOwner management.DocumentOwner
}

func (m Manager) Create(ctx context.Context, options management.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	return m.Creator.Create(ctx, options)
}

func (m Manager) IsOwner(ctx context.Context, did did.DID) (bool, error) {
	// did:nuts DocumentManager uses injected DocumentOwner to check ownership,
	// which lists the private key storage to check if the DID is owned by this node.
	// As did:web stores its private keys in the same way, this leads to duplicates.
	// This manager should only work on did:nuts
	if did.Method != MethodName {
		return false, nil
	}
	return m.DocumentOwner.IsOwner(ctx, did)
}

func (m Manager) ListOwned(ctx context.Context) ([]did.DID, error) {
	// did:nuts DocumentManager uses injected DocumentOwner to check ownership,
	// which lists the private key storage to check if the DID is owned by this node.
	// As did:web stores its private keys in the same way, this leads to duplicates.
	// This manager should only work on did:nuts
	all, err := m.DocumentOwner.ListOwned(ctx)
	if err != nil {
		return nil, err
	}
	var result []did.DID
	for _, curr := range all {
		if curr.Method == MethodName {
			result = append(result, curr)
		}
	}
	return result, err
}

func (m Manager) Resolve(_ did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	return nil, nil, fmt.Errorf("Resolve() is not supported for did:%s", MethodName)
}
