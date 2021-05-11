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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	errors2 "github.com/pkg/errors"
	"net/url"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/shengdoushi/base58"
)

// ModuleName contains the name of this module: Didman
const ModuleName = "Didman"

// ErrDuplicateService is returned when a DID Document already contains a service for the given type
var ErrDuplicateService = errors.New("service type already defined")

// ErrServiceInUse is returned when a service is deleted but in use by other services
var ErrServiceInUse = errors.New("service is referenced by 1 or more services")

// ErrServiceNotFound is returned when the service is not found on a DID
var ErrServiceNotFound = errors.New("service not found in DID Document")

// ErrInvalidServiceQuery is returned when a compound service contains an invalid service reference.
var ErrInvalidServiceQuery = errors.New("service query is invalid")

// ErrReferencedServiceNotAnEndpoint is returned when a compound service contains a reference that does not resolve to a single endpoint URL.
var ErrReferencedServiceNotAnEndpoint = errors.New("referenced service does not resolve to a single endpoint URL")

type didman struct {
	docResolver types.DocResolver
	store       types.Store
	vdr         types.VDR
}

// NewDidmanInstance creates a new didman instance with services set
func NewDidmanInstance(docResolver types.DocResolver, store types.Store, vdr types.VDR) Didman {
	return &didman{
		docResolver: docResolver,
		store:       store,
		vdr:         vdr,
	}
}

func (d *didman) Name() string {
	return ModuleName
}

func (d *didman) AddEndpoint(id did.DID, serviceType string, u url.URL) error {
	logging.Log().Debugf("Adding endpoint (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
	err := d.addService(id, serviceType, u.String(), nil)
	if err == nil {
		logging.Log().Infof("Endpoint added (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
	}
	return err
}

func (d *didman) AddCompoundService(id did.DID, serviceType string, references map[string]ssi.URI) error {
	logging.Log().Debugf("Adding compound service (did: %s, type: %s, references: %v)", id.String(), serviceType, references)

	// Resolve and validate all service references: they must all resolve to a single endpoint URL
	// Cache resolved DID documents because most of the time a compound service will refer the same DID document in all service references.
	documents := make(map[string]*did.Document)
	var err error
	for _, serviceRef := range references {
		referencedDIDStr := serviceRef
		referencedDIDStr.RawQuery = ""
		referencedDIDStr.Fragment = ""
		var document *did.Document
		if document = documents[referencedDIDStr.String()]; document == nil {
			referencedDID, err := did.ParseDID(referencedDIDStr.String())
			if err != nil {
				return err
			}
			document, _, err = d.docResolver.Resolve(*referencedDID, nil)
			if err != nil {
				return err
			}
			documents[referencedDIDStr.String()] = document
		}
		queriedServiceType := serviceRef.Query().Get("type")
		if len(queriedServiceType) == 0 {
			return ErrInvalidServiceQuery
		}
		_, _, err := document.ResolveEndpointURL(queriedServiceType)
		if err != nil {
			return errors2.WithMessage(ErrReferencedServiceNotAnEndpoint, err.Error())
		}
	}

	err = d.addService(id, serviceType, references, nil)
	if err == nil {
		logging.Log().Infof("Compound service added (did: %s, type: %s, references: %s)", id.String(), serviceType, references)
	}
	return err
}

func (d *didman) DeleteService(serviceID ssi.URI) error {
	logging.Log().Debugf("Deleting service (id: %s)", serviceID.String())
	id, err := did.ParseDID(serviceID.String())
	if err != nil {
		return err
	}
	id.Fragment = ""

	doc, meta, err := d.docResolver.Resolve(*id, nil)
	if err != nil {
		return err
	}

	// check for existing use
	if err = d.store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		if referencesService(doc, serviceID) {
			return ErrServiceInUse
		}
		return nil
	}); err != nil {
		return err
	}

	// remove service
	j := 0
	for _, s := range doc.Service {
		if s.ID != serviceID {
			doc.Service[j] = s
			j++
		}
	}
	doc.Service = doc.Service[:j]

	err = d.vdr.Update(*id, meta.Hash, *doc, nil)
	if err == nil {
		logging.Log().Infof("Service removed (id: %s)", serviceID.String())
	}
	return err
}

func (d *didman) UpdateContactInformation(id did.DID, information ContactInformation) (*ContactInformation, error) {
	logging.Log().Debugf("Updating contact information service (did: %s, info: %v)", id.String(), information)
	err := d.addService(id, ContactInformationServiceType, information, func(doc *did.Document) {
		// check for existing contact information and remove it
		i := 0
		for _, s := range doc.Service {
			if s.Type != ContactInformationServiceType {
				doc.Service[i] = s
				i++
			}
		}
		doc.Service = doc.Service[0:i]
	})
	if err == nil {
		logging.Log().Infof("Contact Information Endpoint added (did: %s)", id.String())
	}
	return &information, err
}

// GetContactInformation tries to find the ContactInformation for the indicated DID document.
// Returns nil, nil when no contactInformation for the DID was found.
func (d *didman) GetContactInformation(id did.DID) (*ContactInformation, error) {
	doc, _, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return nil, err
	}

	contactServices := filterContactInfoServices(doc)
	if len(contactServices) > 1 {
		return nil, fmt.Errorf("multiple contact information services found")
	}
	if len(contactServices) == 1 {
		information := &ContactInformation{}
		err = contactServices[0].UnmarshalServiceEndpoint(information)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshall contact info service endpoint: %w", err)
		}
		return information, nil
	}
	return nil, nil
}

func filterContactInfoServices(doc *did.Document) []did.Service {
	var contactServices []did.Service
	for _, service := range doc.Service {
		if service.Type == ContactInformationServiceType {
			contactServices = append(contactServices, service)
		}
	}
	return contactServices
}

func (d *didman) addService(id did.DID, serviceType string, serviceEndpoint interface{}, updater func(*did.Document)) error {
	doc, meta, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return err
	}

	if updater != nil {
		updater(doc)
	}

	// check for duplicate service type
	for _, s := range doc.Service {
		if s.Type == serviceType {
			return ErrDuplicateService
		}
	}

	// construct service with correct ID
	service := did.Service{
		Type:            serviceType,
		ServiceEndpoint: serviceEndpoint,
	}
	service.ID = ssi.URI{}
	service.ID = generateIDForService(id, service)

	// Add on DID Document and update
	doc.Service = append(doc.Service, service)
	return d.vdr.Update(id, meta.Hash, *doc, nil)
}

func generateIDForService(id did.DID, service did.Service) ssi.URI {
	bytes, _ := json.Marshal(service)
	shaBytes := sha256.Sum256(bytes)
	d := id.URI()
	d.Fragment = base58.Encode(shaBytes[:], base58.BitcoinAlphabet)
	return d
}

func referencesService(doc did.Document, serviceID ssi.URI) bool {
	id := serviceID.String()
	for _, s := range doc.Service {
		cs := types.CompoundService{}
		// ignore structures that can not be parsed to compound endpoints
		if err := s.UnmarshalServiceEndpoint(&cs); err == nil {
			for _, v := range cs {
				if v == id {
					return true
				}
			}
		}
	}
	return false
}
