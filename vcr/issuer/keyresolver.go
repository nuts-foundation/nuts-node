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

package issuer

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// vdrKeyResolver resolves private keys based upon the VDR document resolver
type vdrKeyResolver struct {
	publicKeyResolver  vdr.KeyResolver
	privateKeyResolver crypto.KeyResolver
}

// ResolveAssertionKey is a convenience method which tries to find a assertionKey on in the VDR for a given issuerDID.
func (r vdrKeyResolver) ResolveAssertionKey(ctx context.Context, issuerDID did.DID) (crypto.Key, error) {
	kid, _, err := r.publicKeyResolver.ResolveKey(issuerDID, nil, vdr.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	key, err := r.privateKeyResolver.Resolve(ctx, kid.String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve assertionKey: could not resolve key from keyStore: %w", err)
	}

	return key, err
}
