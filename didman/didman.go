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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/didman/log"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/shengdoushi/base58"
)

// ModuleName contains the name of this module: Didman
const ModuleName = "Didman"

// ErrServiceInUse is returned when a service is deleted but in use by other services
var ErrServiceInUse = errors.New("service is referenced by 1 or more services")

// ErrReferencedServiceNotAnEndpoint is returned when a compound service contains a reference that does not resolve to a single endpoint URL.
type ErrReferencedServiceNotAnEndpoint struct {
	Cause error
}

// Error returns the error message.
func (e ErrReferencedServiceNotAnEndpoint) Error() string {
	return fmt.Sprintf("referenced service does not resolve to a single endpoint URL: %s", e.Cause)
}

// Is checks whether the other error is also a ErrReferencedServiceNotAnEndpoint
func (e ErrReferencedServiceNotAnEndpoint) Is(other error) bool {
	return fmt.Sprintf("%T", e) == fmt.Sprintf("%T", other)
}

type didman struct {
	jsonldManager   jsonld.JSONLD
	docResolver     types.DocResolver
	serviceResolver doc.ServiceResolver
	store           types.Store
	vdr             types.VDR
	vcr             vcr.VCR
}

// NewDidmanInstance creates a new didman instance with services set
func NewDidmanInstance(docResolver types.DocResolver, store types.Store, vdr types.VDR, vcr vcr.VCR, jsonldManager jsonld.JSONLD) Didman {
	return &didman{
		docResolver:     docResolver,
		serviceResolver: doc.NewServiceResolver(docResolver),
		store:           store,
		vdr:             vdr,
		vcr:             vcr,
		jsonldManager:   jsonldManager,
	}
}

func (d *didman) Name() string {
	return ModuleName
}

func (d *didman) AddEndpoint(id did.DID, serviceType string, u url.URL) (*did.Service, error) {
	log.Logger().Debugf("Adding endpoint (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
	service, err := d.addService(id, serviceType, u.String(), nil)
	if err == nil {
		log.Logger().Infof("Endpoint added (did: %s, type: %s, url: %s)", id.String(), serviceType, u.String())
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
		return types.ErrServiceNotFound
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

func (d *didman) AddCompoundService(id did.DID, serviceType string, endpoints map[string]ssi.URI) (*did.Service, error) {
	log.Logger().Debugf("Adding compound service (did: %s, type: %s, endpoints: %v)", id.String(), serviceType, endpoints)
	if err := d.validateCompoundServiceEndpoint(endpoints); err != nil {
		return nil, err
	}

	// transform service references to map[string]interface{}
	serviceEndpoint := map[string]interface{}{}
	for k, v := range endpoints {
		serviceEndpoint[k] = v.String()
	}

	service, err := d.addService(id, serviceType, serviceEndpoint, nil)
	if err == nil {
		log.Logger().Infof("Compound service added (did: %s, type: %s, endpoints: %s)", id.String(), serviceType, endpoints)
	}

	return service, err
}

func (d *didman) GetCompoundServiceEndpoint(id did.DID, compoundServiceType string, endpointType string, resolveReferences bool) (string, error) {
	document, _, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return "", err
	}

	referenceDepth := 0
	documentsCache := map[string]*did.Document{document.ID.String(): document}

	// First, resolve the compound endpoint
	compoundService, err := d.serviceResolver.ResolveEx(doc.MakeServiceReference(id, compoundServiceType), referenceDepth, doc.DefaultMaxServiceReferenceDepth, documentsCache)
	if err != nil {
		return "", ErrReferencedServiceNotAnEndpoint{Cause: fmt.Errorf("unable to resolve compound service: %w", err)}
	}

	// Second, resolve the endpoint in the compound service
	endpoints := make(map[string]string, 0)
	err = compoundService.UnmarshalServiceEndpoint(&endpoints)
	if err != nil {
		return "", ErrReferencedServiceNotAnEndpoint{Cause: fmt.Errorf("referenced service is not a compound service: %w", err)}
	}
	endpoint := endpoints[endpointType]
	if endpoint == "" {
		return "", types.ErrServiceNotFound
	}
	if resolveReferences && doc.IsServiceReference(endpoint) {
		endpointURI, err := ssi.ParseURI(endpoint)
		if err != nil {
			// Not sure when this could ever happen
			return "", err
		}
		resolvedEndpoint, err := d.serviceResolver.ResolveEx(*endpointURI, referenceDepth, doc.DefaultMaxServiceReferenceDepth, documentsCache)
		if err != nil {
			return "", err
		}
		err = resolvedEndpoint.UnmarshalServiceEndpoint(&endpoint)
		if err != nil {
			return "", ErrReferencedServiceNotAnEndpoint{Cause: err}
		}
		return endpoint, nil
	}
	return endpoint, nil
}

func (d *didman) DeleteService(serviceID ssi.URI) error {
	log.Logger().Debugf("Deleting service (id: %s)", serviceID.String())
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
		return types.ErrServiceNotFound
	}
	doc.Service = doc.Service[:j]

	err = d.vdr.Update(*id, meta.Hash, *doc, nil)
	if err == nil {
		log.Logger().Infof("Service removed (id: %s)", serviceID.String())
	}
	return err
}

func (d *didman) UpdateContactInformation(id did.DID, information ContactInformation) (*ContactInformation, error) {
	log.Logger().Debugf("Updating contact information service (did: %s, info: %v)", id.String(), information)

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
		log.Logger().Infof("Contact Information Endpoint added (did: %s)", id.String())
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

func (d *didman) SearchOrganizations(ctx context.Context, query string, didServiceType *string) ([]OrganizationSearchResult, error) {
	organizations, err := d.vcr.SearchConcept(ctx, concept.OrganizationConcept, false, map[string]string{"credentialSubject.organization.name": query})
	if err != nil {
		return nil, err
	}
	// Retrieve DID Documents of found organizations
	var didDocuments []*did.Document
	didDocuments, organizations, err = d.resolveOrganizationDIDDocuments(organizations)
	if err != nil {
		return nil, err
	}

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
		organization, ok := organizations[i]["organization"].(map[string]interface{})
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

// resolveOrganizationDIDDocuments takes a slice of organization concepts and tries to resolve the corresponding DID document for each.
// If a DID document isn't found or it is deactivated the organization is filtered from the concepts slice (reslicing the given slice) and omitted from the DID documents slice.
// If any other error occurs, it is returned.
func (d *didman) resolveOrganizationDIDDocuments(organizations []concept.Concept) ([]*did.Document, []concept.Concept, error) {
	didDocuments := make([]*did.Document, len(organizations))
	j := 0
	for i, organization := range organizations {
		document, organizationDID, err := d.resolveOrganizationDIDDocument(organization)
		if err != nil && !(errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrDeactivated)) {
			return nil, nil, err
		}
		if document == nil {
			// DID Document might be deactivated, so just log a warning and omit this entry from the search.
			log.Logger().Warnf("Unable to resolve organization DID Document (DID=%s): %v", organizationDID, err)
			continue
		}
		didDocuments[j] = document
		organizations[j] = organizations[i]
		j++
	}
	// Reslice to omit results which' DID Document could not be resolved
	didDocuments = didDocuments[:j]
	organizations = organizations[:j]
	return didDocuments, organizations, nil
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
	document, _, err := d.docResolver.Resolve(*organizationDID, nil)
	return document, *organizationDID, err
}

// validateCompoundServiceEndpoint validates the serviceEndpoint of a compound service. The serviceEndpoint is passed
// as a map of URIs that are either absolute URL endpoints or references that resolve to absolute URL endpoints. If validation fails an error is returned.
// If all endpoints are valid nil is returned.
func (d *didman) validateCompoundServiceEndpoint(endpoints map[string]ssi.URI) error {
	// Cache resolved DID documents because most of the time a compound service will refer the same DID document in all service references.
	cache := make(map[string]*did.Document, 0)
	for _, serviceRef := range endpoints {
		if doc.IsServiceReference(serviceRef.String()) {
			err := doc.ValidateServiceReference(serviceRef)
			if err != nil {
				return ErrReferencedServiceNotAnEndpoint{Cause: err}
			}
			_, err = d.serviceResolver.ResolveEx(serviceRef, 0, doc.DefaultMaxServiceReferenceDepth, cache)
			if err != nil {
				return ErrReferencedServiceNotAnEndpoint{Cause: err}
			}
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
