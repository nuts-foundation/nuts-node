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

package client

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
)

// Invoker is the interface for the client that invokes the remote Discovery Service.
type Invoker interface {
	// Register registers a Verifiable Presentation on the remote Discovery Service.
	Register(ctx context.Context, serviceEndpointURL string, presentation vc.VerifiablePresentation) error

	// Get retrieves Verifiable Presentations from the remote Discovery Service, that were added since the given tag.
	// If tag is nil, all Verifiable Presentations are retrieved.
	Get(ctx context.Context, serviceEndpointURL string, tag *discovery.Tag) ([]vc.VerifiablePresentation, *discovery.Tag, error)
}
