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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/shengdoushi/base58"
	"net/url"
)

// ModuleName contains the name of this module: Didman
const ModuleName = "Didman"

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
	vcr         vcr.VCR
}

// NewDidmanInstance creates a new didman instance with services set
func NewDidmanInstance(docResolver types.DocResolver, store types.Store, vdr types.VDR, vcr vcr.VCR) Didman {
	return &didman{
		docResolver: docResolver,
		store:       store,
		vdr:         vdr,
		vcr:         vcr,
	}
}

func (d *didman) Name() string {
	return ModuleName
}

func (d *didman) AddEndpoint(id did.DID, serviceType string, u url.URL) (*did.Service, error) {
	logging.Log().Debugf("Adding endpoint (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
	service, err := d.addService(id, serviceType, u.String(), nil)
	if err == nil {
		logging.Log().Infof("Endpoint added (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
	}
	return service, err
}

func (d *didman) DeleteEndpointsByType(id did.DID, serviceType string) error {
	doc, _, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return err
	}

	found := false
	for _, s := range doc.Service {
		if s.Type == serviceType {
			found = true
			if err = d.DeleteService(s.ID); err != nil {
				return err
			}
		}
	}
	if !found {
		return ErrServiceNotFound
	}
	return nil
}

func (d *didman) GetCompoundServices(id did.DID) ([]did.Service, error) {
	doc, _, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return nil, err
	}

	return filterCompoundServices(doc), nil
}

func (d *didman) AddCompoundService(id did.DID, serviceType string, references map[string]ssi.URI) (*did.Service, error) {
	logging.Log().Debugf("Adding compound service (did: %s, type: %s, references: %v)", id.String(), serviceType, references)
	if err := d.validateCompoundServiceEndpoint(references); err != nil {
		return nil, err
	}

	// transform service references to map[string]interface{}
	serviceEndpoint := map[string]interface{}{}
	for k, v := range references {
		serviceEndpoint[k] = v.String()
	}

	service, err := d.addService(id, serviceType, serviceEndpoint, nil)
	if err == nil {
		logging.Log().Infof("Compound service added (did: %s, type: %s, references: %s)", id.String(), serviceType, references)
	}

	return service, err
}

func (d *didman) DeleteService(serviceID ssi.URI) error {
	logging.Log().Debugf("Deleting service (id: %s)", serviceID.String())
	id, err := did.ParseDIDURL(serviceID.String())
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
	if j == len(doc.Service) {
		return ErrServiceNotFound
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

	// transform ContactInformation to map[string]interface{}
	serviceEndpoint := map[string]interface{}{
		"name":    information.Name,
		"email":   information.Email,
		"phone":   information.Phone,
		"website": information.Website,
	}

	_, err := d.addService(id, ContactInformationServiceType, serviceEndpoint, func(doc *did.Document) {
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

	contactServices := filterServices(doc, ContactInformationServiceType)
	if len(contactServices) > 1 {
		return nil, fmt.Errorf("multiple contact information services found")
	}
	if len(contactServices) == 1 {
		information := &ContactInformation{}
		err = contactServices[0].UnmarshalServiceEndpoint(information)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal contact info service endpoint: %w", err)
		}
		return information, nil
	}
	return nil, nil
}

func (d *didman) SearchOrganizations(query string, didServiceType *string) ([]OrganizationSearchResult, error) {
	organizations, err := d.vcr.Search(concept.OrganizationConcept, map[string]string{concept.OrganizationName: query})
	if err != nil {
		return nil, err
	}
	// Retrieve DID Documents of found organizations
	didDocuments := make([]*did.Document, len(organizations))
	j := 0
	for i, organization := range organizations {
		document, organizationDID, err := d.resolveOrganizationDIDDocument(organization)
		if err != nil && !errors.Is(types.ErrNotFound, err){
			return nil, err
		}
		if document == nil {
			// DID Document might be deactivated, so just log a warning and omit this entry from the search.
			logging.Log().Warnf("Unable to resolve organization DID Document (DID=%s): %v", organizationDIDStr, err)
			continue
		}
		didDocuments[j] = document
		organizations[j] = organizations[i]
		j++
	}
	// Reslice to omit results which' DID Document could not be resolved
	didDocuments = didDocuments[:j]
	organizations = organizations[:j]

	// If specified, filter on DID service type
	if didServiceType != nil && len(*didServiceType) > 0 {
		j := 0
		for i := 0; i < len(organizations); i++ {
			// Check if this organization's DID Document has a service that matches the given type
			if len(filterServices(didDocuments[i], *didServiceType)) > 0 {
				organizations[j] = organizations[i]
				didDocuments[j] = didDocuments[i]
				j++
			}
		}
		// Reslice to omit results which' DID Document did not contain the given service type
		didDocuments = didDocuments[:j]
		organizations = organizations[:j]
	}

	// Convert organization concepts and DID documents to search results
	results := make([]OrganizationSearchResult, len(organizations))
	for i := range organizations {
		organization, ok := organizations[i]["organization"].(concept.Concept)
		if !ok {
			return nil, errors.New("unable to map organization to concept")
		}
		results[i] = OrganizationSearchResult{
			DIDDocument:  *didDocuments[i],
			Organization: organization,
		}
	}

	return results, nil
}

func (d *didman) resolveOrganizationDIDDocument(organization concept.Concept) (*did.Document, did.DID, error) {
	organizationDIDStr, err := organization.GetString(concept.SubjectField)
	if err != nil {
		return nil, did.DID{}, fmt.Errorf("unable to get DID from organization concept: %w", err)
	}
	organizationDID, err := did.ParseDID(organizationDIDStr)
	if err != nil {
		return nil, did.DID{}, fmt.Errorf("unable to parse DID from organization concept: %w", err)
	}
	document, _, err := d.store.Resolve(*organizationDID, nil)
	return document, *organizationDID, err
}

// validateCompoundServiceEndpoint validates the serviceEndpoint of a compound service. The serviceEndpoint is passed
// as a map of service references that must be resolvable to concrete URL endpoints. If validation fails an error is returned.
// If all references can be resolved nil is returned.
func (d *didman) validateCompoundServiceEndpoint(references map[string]ssi.URI) error {
	// Cache resolved DID documents because most of the time a compound service will refer the same DID document in all service references.
	documents := make(map[string]*did.Document)
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
			return fmt.Errorf("%w: %s", ErrReferencedServiceNotAnEndpoint, err.Error())
		}
	}
	return nil
}

func filterCompoundServices(doc *did.Document) []did.Service {
	var compoundServices []did.Service
	for _, service := range doc.Service {
		if service.Type == ContactInformationServiceType {
			continue
		}
		if _, ok := service.ServiceEndpoint.(map[string]interface{}); ok {
			compoundServices = append(compoundServices, service)
		}
	}
	return compoundServices
}

func filterServices(doc *did.Document, serviceType string) []did.Service {
	var contactServices []did.Service
	for _, service := range doc.Service {
		if service.Type == serviceType {
			contactServices = append(contactServices, service)
		}
	}
	return contactServices
}

func (d *didman) addService(id did.DID, serviceType string, serviceEndpoint interface{}, preprocessor func(*did.Document)) (*did.Service, error) {
	doc, meta, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return nil, err
	}

	if preprocessor != nil {
		preprocessor(doc)
	}

	// check for duplicate service type
	for _, s := range doc.Service {
		if s.Type == serviceType {
			return nil, types.ErrDuplicateService
		}
	}

	// construct service with correct ID
	service := &did.Service{
		Type:            serviceType,
		ServiceEndpoint: serviceEndpoint,
	}
	service.ID = ssi.URI{}
	service.ID = generateIDForService(id, *service)

	// Add on DID Document and update
	doc.Service = append(doc.Service, *service)
	if err = d.vdr.Update(id, meta.Hash, *doc, nil); err != nil {
		return nil, err
	}
	return service, nil
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
