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
	"github.com/nuts-foundation/go-did/vc"
)

// ErrServiceNotFound is returned when a service (ID) is not found in the discovery service.
var ErrServiceNotFound = errors.New("discovery service not found")

// ErrPresentationAlreadyExists is returned when a presentation is added to the discovery service,
// but a presentation with this ID already exists.
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

// ErrPresentationRegistrationFailed indicates registration of a presentation on a remote Discovery Service failed.
var ErrPresentationRegistrationFailed = errors.New("registration of Verifiable Presentation on remote Discovery Service failed")

var ErrDIDMethodsNotSupported = errors.New("DID methods not supported")

// authServerURLField is the field name for the authServerURL in the DiscoveryRegistrationCredential.
// it is used to resolve authorization server metadata and thus the endpoints for a service entry.
const authServerURLField = "authServerURL"

// Server defines the API for Discovery Servers.
type Server interface {
	// Register registers a presentation on the given Discovery Service.
	// If the presentation is not valid, or it does not conform to the Service ServiceDefinition, it returns an error.
	// If the node is not configured as server for the given serviceID, the call will be forwarded to the configured server.
	Register(context context.Context, serviceID string, presentation vc.VerifiablePresentation) error
	// Get retrieves the presentations for the given service, starting from the given timestamp.
	// If the node is not configured as server for the given serviceID, the call will be forwarded to the configured server.
	Get(context context.Context, serviceID string, startAfter int) (map[string]vc.VerifiablePresentation, string, int, error)
}

// Client defines the API for Discovery Clients.
type Client interface {
	// Search searches for presentations which credential(s) match the given query.
	// Query parameters are formatted as simple JSON paths, e.g. "issuer" or "credentialSubject.name".
	// It returns an ErrServiceNotFound if the service invalid/unknown.
	Search(serviceID string, query map[string]string) ([]SearchResult, error)

	// ActivateServiceForSubject causes a subject to be registered for a Discovery Service.
	// Registration of all DIDs of the subject will be attempted immediately, and automatically refreshed.
	// If the function is called again for the same service/DID combination, it will try to refresh the registration.
	// parameters are added as credentialSubject to a DiscoveryRegistrationCredential holder credential.
	// It returns an ErrServiceNotFound or didsubject.ErrSubjectNotFound if the service or subject is invalid/unknown.
	ActivateServiceForSubject(ctx context.Context, serviceID, subjectID string, parameters map[string]interface{}) error

	// DeactivateServiceForSubject stops registration of a subject on a Discovery Service.
	// It also tries to remove all active registrations of the subject from the Discovery Service.
	// If removal of one or more active registration fails a ErrPresentationRegistrationFailed may be returned. The failed registrations will be removed when they expire.
	// It returns an ErrServiceNotFound or didsubject.ErrSubjectNotFound if the service or subject is invalid/unknown.
	DeactivateServiceForSubject(ctx context.Context, serviceID, subjectID string) error

	// Services returns the list of services that are registered on this client.
	Services() []ServiceDefinition

	// GetServiceActivation returns the activation status of a subject on a Discovery Service.
	// The boolean indicates whether the subject is activated on the Discovery Service (ActivateServiceForSubject() has been called).
	// It also returns the Verifiable Presentations for all DIDs of the subject that are registered on the Discovery Service, if any.
	// It returns an ErrServiceNotFound or didsubject.ErrSubjectNotFound if the service or subject is invalid/unknown.
	// It returns a RegistrationRefreshError with additional information if the last refresh of the service failed (activation status and VPs are still returned).
	// The time of the last error is added in the error message.
	GetServiceActivation(ctx context.Context, serviceID, subjectID string) (bool, []vc.VerifiablePresentation, error)
}

// SearchResult is a single result of a search operation.
type SearchResult struct {
	// Presentation is the Verifiable Presentation that was matched.
	Presentation vc.VerifiablePresentation `json:"vp"`
	// Fields is a map of Input Descriptor Constraint Fields from the Discovery Service's Presentation Definition.
	// The keys are the Input Descriptor IDs mapped to the values from the credential(s) inside the Presentation.
	// It only includes constraint fields that have an ID.
	Fields map[string]interface{} `json:"fields"`
	// Parameters is a map of parameters that were used during registration.
	Parameters map[string]interface{} `json:"registrationParameters"`
}

type presentationVerifier func(definition ServiceDefinition, presentation vc.VerifiablePresentation) error

// XForwardedHostContextKey is the context key for the X-Forwarded-Host header.
type XForwardedHostContextKey struct{}

// RegistrationRefreshError is returned from GetServiceRefreshError.
type RegistrationRefreshError struct {
	Underlying error
}

func (r RegistrationRefreshError) Error() string {
	return r.Underlying.Error()
}
