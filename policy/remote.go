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

package policy

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/policy/api/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

var _ PDPBackend = remote{}

type remote struct {
	address string
	client  client.HTTPClient
}

func (b remote) PresentationDefinitions(ctx context.Context, authorizer did.DID, scope string) (pe.WalletOwnerMapping, error) {
	return b.client.PresentationDefinitions(ctx, b.address, authorizer, scope)
}

func (b remote) Authorized(ctx context.Context, requestInfo client.AuthorizedRequest) (bool, error) {
	return b.client.Authorized(ctx, b.address, requestInfo)
}
