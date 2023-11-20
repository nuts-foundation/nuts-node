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

package discovery

import (
	"errors"
	"github.com/nuts-foundation/go-did/vc"
)

// Timestamp is value that references a point in the list.
// It is used by clients to request new entries since their last query.
// It's implemented as lamport timestamp (https://en.wikipedia.org/wiki/Lamport_timestamp);
// it is incremented when a new entry is added to the list.
// Pass 0 to start at the beginning of the list.
type Timestamp uint64

// ErrServiceNotFound is returned when a service (ID) is not found in the discovery service.
var ErrServiceNotFound = errors.New("discovery service not found")

// ErrPresentationAlreadyExists is returned when a presentation is added to the discovery service,
// but a presentation with this ID already exists.
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

// Server defines the API for Discovery Servers.
type Server interface {
	// Add registers a presentation on the given Discovery Service.
	// If the presentation is not valid or it does not conform to the Service Definition, it returns an error.
	Add(serviceID string, presentation vc.VerifiablePresentation) error
	// Get retrieves the presentations for the given service, starting at the given timestamp.
	Get(serviceID string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error)
}

// Client defines the API for Discovery Clients.
type Client interface {
	Search(serviceID string, query map[string]string) ([]vc.VerifiablePresentation, error)
}
