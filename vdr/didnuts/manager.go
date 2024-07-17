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
	ssi "github.com/nuts-foundation/go-did"
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
	Manipulator   management.DocManipulator
}

func (m Manager) Deactivate(ctx context.Context, id did.DID) error {
	return m.Manipulator.Deactivate(ctx, id)
}

func (m Manager) Create(ctx context.Context, options management.CreationOptions) (*did.Document, crypto.Key, error) {
	return m.Creator.Create(ctx, options)
}

func (m Manager) Resolve(_ did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	return nil, nil, fmt.Errorf("Resolve() is not supported for did:%s", MethodName)
}

func (m Manager) CreateService(_ context.Context, _ did.DID, _ did.Service) (*did.Service, error) {
	return nil, fmt.Errorf("CreateService() is not supported for did:%s", MethodName)
}

func (m Manager) UpdateService(_ context.Context, _ did.DID, _ ssi.URI, _ did.Service) (*did.Service, error) {
	return nil, fmt.Errorf("UpdateService() is not supported for did:%s", MethodName)
}

func (m Manager) DeleteService(_ context.Context, _ did.DID, _ ssi.URI) error {
	return fmt.Errorf("DeleteService() is not supported for did:%s", MethodName)
}
