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

package didman

import (
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"net/url"
)

// ContactInformationServiceType contains the DID service type used for services that contain node contact information.
const ContactInformationServiceType = "node-contact-info"

// Didman groups all high-level methods for manipulating DID Documents
type Didman interface {
	CompoundServiceResolver

	// AddEndpoint adds a service to a DID Document. The serviceEndpoint is set to the given URL.
	// It returns ErrDuplicateService if a service with the given type already exists.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	AddEndpoint(ctx context.Context, id did.DID, serviceType string, endpoint url.URL) (*did.Service, error)

	// UpdateEndpoint updates the serviceEndpoint of a service in a DID Document. The serviceEndpoint is set to the given URL.
	// It can return various errors from DocResolver.Resolve and VDR.Update.
	UpdateEndpoint(ctx context.Context, id did.DID, serviceType string, endpoint url.URL) (*did.Service, error)

	// DeleteEndpointsByType takes a did and type and removes all endpoint with the type from the DID Document.
	// It returns ErrServiceNotFound if no services with the given type can't be found in the DID Document.
	// It returns ErrServiceInUse if the service is referenced by other services.
	// It can also return various errors from DocResolver.Resolve
	DeleteEndpointsByType(ctx context.Context, id did.DID, serviceType string) error

	// DeleteService removes a service from a DID Document.
	// It returns ErrServiceInUse if the service is referenced by other services.
	// It returns ErrServiceNotFound if the service can't be found in the DID Document.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	DeleteService(ctx context.Context, id ssi.URI) error

	// AddCompoundService adds a compound endpoint to a DID Document.
	// It returns ErrDuplicateService if a service with the given type already exists.
	// It returns didservice.DIDServiceQueryError if one of the service references is invalid.
	// It returns ErrReferencedServiceNotAnEndpoint if one of the references does not resolve to a single endpoint URL.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	AddCompoundService(ctx context.Context, id did.DID, serviceType string, endpoints map[string]ssi.URI) (*did.Service, error)

	// UpdateCompoundService updates a compound endpoint in a DID Document.
	// It returns didservice.DIDServiceQueryError if one of the service references is invalid.
	// It returns ErrReferencedServiceNotAnEndpoint if one of the references does not resolve to a single endpoint URL.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	UpdateCompoundService(ctx context.Context, id did.DID, serviceType string, endpoints map[string]ssi.URI) (*did.Service, error)

	// UpdateContactInformation adds or updates the compoundService with type equal to node-contact-info with provided
	// contact information to the DID Document.
	// It returns the contact information when the update was successful.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	UpdateContactInformation(ctx context.Context, id did.DID, information ContactInformation) (*ContactInformation, error)

	// GetContactInformation finds and returns the contact information from the provided DID Document.
	// Returns nil, nil when no contactInformation for the DID was found.
	// It can also return various errors from DocResolver.Resolve
	GetContactInformation(id did.DID) (*ContactInformation, error)

	// SearchOrganizations searches VCR for organizations which's name matches the given query.
	// It then optionally filters on those which have a service of the specified type on their DID Document.
	SearchOrganizations(ctx context.Context, query string, didServiceType *string) ([]OrganizationSearchResult, error)
}

// CompoundServiceResolver defines high-level operations for resolving services of DID documents.
type CompoundServiceResolver interface {
	// GetCompoundServiceEndpoint retrieves the endpoint with the specified endpointType from the specified compound service.
	// It returns the serviceEndpoint of the specified service (which must be an absolute URL endpoint).
	// If resolveReferences is true and the specified endpointType contains a reference, it is resolved and the referenced endpoint is returned instead.
	// It returns ErrServiceNotFound if the specified compound service or endpoint can't be found in the DID Document.
	// It returns didservice.DIDServiceQueryError if the endpoint doesn't contain a (valid) reference and resolveReferences = true.
	// It returns ErrServiceReferenceToDeep if the endpoint reference is nested too deep.
	GetCompoundServiceEndpoint(id did.DID, compoundServiceType string, endpointType string, resolveReferences bool) (string, error)

	// GetCompoundServices returns a list of all compoundServices defined on the given DID document.
	// It does not include special compound services like ContactInformation
	// It can also return various errors from DocResolver.Resolve
	GetCompoundServices(id did.DID) ([]did.Service, error)
}

// ContactInformation contains set of contact information entries
type ContactInformation struct {

	// Email contains the email address for normal priority support
	Email string `json:"email"`

	// Name contains the commonly known name of the service provider
	Name string `json:"name"`

	// Phone contains a phone number for high priority support
	Phone string `json:"phone"`

	// Website contains the URL of the public website of this Service Provider. Can point to a Nuts specific page with more information about the node and how to contact.
	Website string `json:"website"`
}

// OrganizationSearchResult is returned by SearchOrganizations and associates a resulting organization with its DID Document.
type OrganizationSearchResult struct {
	// DIDDocument contains the organization's DID Document.
	DIDDocument did.Document `json:"didDocument"`
	// Organization contains the organization's information derived from its Verifiable Credential.
	Organization map[string]interface{} `json:"organization"`
}
