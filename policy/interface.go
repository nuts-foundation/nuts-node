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
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/policy/api/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// ModuleName is the name of the policy module
const ModuleName = "policy"

var ErrNotFound = errors.New("not found")

// PDPBackend is the interface for the policy backend
// Both the remote and local policy backend implement this interface
type PDPBackend interface {
	// PresentationDefinitions returns the PresentationDefinitions (as PEXPolicy) for the given scope
	// scopes are space delimited. It's up to the backend to decide how to handle this
	PresentationDefinitions(ctx context.Context, authorizer did.DID, scope string) ([]pe.MultiPEX, error)

	// Authorized returns true if the policy backends authorizes the given request information fall within the policy definition
	Authorized(ctx context.Context, requestInfo client.AuthorizedRequest) (bool, error)
}
