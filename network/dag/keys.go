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
 */

package dag

import (
	"crypto"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/service"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// SourceTXKeyResolver implements the SourceTXKeyResolver interface.
type SourceTXKeyResolver struct {
	Resolver types.DIDResolver
}

func (r SourceTXKeyResolver) ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error) {
	// try all keys, continue when err == types.ErrNotFound
	for _, h := range sourceTransactionsRefs {
		publicKey, err := resolvePublicKey(r.Resolver, kid, types.ResolveMetadata{
			SourceTransaction: &h,
		})
		if err == nil {
			return publicKey, nil
		}
		if err != types.ErrNotFound {
			return nil, err
		}
	}

	return nil, types.ErrNotFound
}

func resolvePublicKey(resolver types.DIDResolver, kid string, metadata types.ResolveMetadata) (crypto.PublicKey, error) {
	id, err := did.ParseDIDURL(kid)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", kid, err)
	}
	holder, _ := service.GetDIDFromURL(kid) // can't fail, already parsed
	doc, _, err := resolver.Resolve(holder, &metadata)
	if err != nil {
		return nil, err
	}

	vm := doc.VerificationMethod.FindByID(*id)
	if vm == nil {
		return nil, types.ErrKeyNotFound
	}

	return vm.PublicKey()
}
