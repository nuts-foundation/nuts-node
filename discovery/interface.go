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
	"context"
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"math"
	"strconv"
	"strings"
)

// Tag is value that references a point in the list.
// It is used by clients to request new entries since their last query.
// It is opaque for clients: they should not try to interpret it.
// The server who issued the tag can interpret it as Lamport timestamp.
type Tag string

// Timestamp decodes the Tag into a Timestamp, which is a monotonically increasing integer value (Lamport timestamp).
// Tags should only be decoded by the server who issued it, so the server should provide the stored tag prefix.
// The tag prefix is a random value that is generated when the service is created.
// It is not a secret; it only makes sure clients receive the complete presentation list when they switch servers for a specific Discovery Service:
// servers return the complete list when the client passes a timestamp the server can't decode.
func (t Tag) Timestamp(tagPrefix string) *Timestamp {
	trimmed := strings.TrimPrefix(string(t), tagPrefix)
	if len(trimmed) == len(string(t)) {
		// Invalid tag prefix
		return nil
	}
	result, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		// Not a number
		return nil
	}
	if result < 0 || result > math.MaxUint64 {
		// Invalid uint64
		return nil
	}
	lamport := Timestamp(result)
	return &lamport
}

// Empty returns true if the Tag is empty.
func (t Tag) Empty() bool {
	return len(t) == 0
}

// Timestamp is the interpreted Tag.
// It's implemented as lamport timestamp (https://en.wikipedia.org/wiki/Lamport_timestamp);
// it is incremented when a new entry is added to the list.
// Pass 0 to start at the beginning of the list.
type Timestamp uint64

// Tag returns the Timestamp as Tag.
func (l Timestamp) Tag(serviceSeed string) Tag {
	return Tag(serviceSeed + strconv.FormatUint(uint64(l), 10))
}

func (l Timestamp) Increment() Timestamp {
	return l + 1
}

// ErrServiceNotFound is returned when a service (ID) is not found in the discovery service.
var ErrServiceNotFound = errors.New("discovery service not found")

// ErrPresentationAlreadyExists is returned when a presentation is added to the discovery service,
// but a presentation with this ID already exists.
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

// ErrPresentationRegistrationFailed indicates registration of a presentation on a remote Discovery Service failed.
var ErrPresentationRegistrationFailed = errors.New("registration of Verifiable Presentation on remote Discovery Service failed")

// Server defines the API for Discovery Servers.
type Server interface {
	// Register registers a presentation on the given Discovery Service.
	// If the presentation is not valid, or it does not conform to the Service ServiceDefinition, it returns an error.
	Register(serviceID string, presentation vc.VerifiablePresentation) error
	// Get retrieves the presentations for the given service, starting at the given timestamp.
	Get(serviceID string, startAt *Tag) ([]vc.VerifiablePresentation, *Tag, error)
}

// Client defines the API for Discovery Clients.
type Client interface {
	// Search searches for presentations which credential(s) match the given query.
	// Query parameters are formatted as simple JSON paths, e.g. "issuer" or "credentialSubject.name".
	Search(serviceID string, query map[string]string) ([]SearchResult, error)

	// ActivateServiceForDID causes a DID, in the form of a Verifiable Presentation, to be registered on a Discovery Service.
	// Registration will be attempted immediately, and automatically refreshed.
	// If the initial registration fails with ErrPresentationRegistrationFailed, registration will be retried.
	// If the function is called again for the same service/DID combination, it will try to refresh the registration.
	// It returns an error if the service or DID is invalid/unknown.
	ActivateServiceForDID(ctx context.Context, serviceID string, subjectDID did.DID) error

	// DeactivateServiceForDID removes the registration of a DID on a Discovery Service.
	// It returns an error if the service or DID is invalid/unknown.
	DeactivateServiceForDID(ctx context.Context, serviceID string, subjectDID did.DID) error
}

// SearchResult is a single result of a search operation.
type SearchResult struct {
	// Presentation is the Verifiable Presentation that was matched.
	Presentation vc.VerifiablePresentation `json:"vp"`
	// Fields is a map of Input Descriptor Constraint Fields from the Discovery Service's Presentation Definition.
	// The keys are the Input Descriptor IDs mapped to the values from the credential(s) inside the Presentation.
	// It only includes constraint fields that have an ID.
	Fields map[string]interface{} `json:"fields"`
}
