/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package v2

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR vdr.VDR
}

func (w Wrapper) ResolveStatusCode(err error) int {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) CreateDID(ctx context.Context, request CreateDIDRequestObject) (CreateDIDResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) DeleteDID(ctx context.Context, request DeleteDIDRequestObject) (DeleteDIDResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) ResolveDID(ctx context.Context, request ResolveDIDRequestObject) (ResolveDIDResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) AddService(ctx context.Context, request AddServiceRequestObject) (AddServiceResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) DeleteService(ctx context.Context, request DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) UpdateService(ctx context.Context, request UpdateServiceRequestObject) (UpdateServiceResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) AddVerificationMethod(ctx context.Context, request AddVerificationMethodRequestObject) (AddVerificationMethodResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) DeleteVerificationMethod(ctx context.Context, request DeleteVerificationMethodRequestObject) (DeleteVerificationMethodResponseObject, error) {
	//TODO implement me
	panic("implement me")
}
