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
	"net/url"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

// ContactInformationServiceType contains the DID service type used for services that contain node contact information.
const ContactInformationServiceType = "node-contact-info"

// Didman groups all high-level methods for manipulating DID Documents
type Didman interface {
	// AddEndpoint adds a service to a DID Document. The serviceEndpoint is set to the given URL.
	// It returns ErrDuplicateService if a service with the given type already exists.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	AddEndpoint(id did.DID, serviceType string, u url.URL) error
	// DeleteService removes a service from a DID Document.
	// It returns ErrServiceInUse if the service is referenced by other services.
	// It returns ErrServiceNotFound if the service can't be found in the DID Document.
	// It can also return various errors from DocResolver.Resolve and VDR.Update
	DeleteService(id ssi.URI) error

	UpdateContactInformation(id did.DID, information ContactInformation) (*ContactInformation, error)

	GetContactInformation(id did.DID) (*ContactInformation, error)
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
