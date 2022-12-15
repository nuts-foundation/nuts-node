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
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
	"sync"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/didman/log"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/shengdoushi/base58"
)

// ModuleName contains the name of this module: Didman
const ModuleName = "Didman"

// ErrServiceInUse is returned when a service is deleted but in use by other services
var ErrServiceInUse = errors.New("service is referenced by 1 or more services")

// keyedMutex provides a way of preventing parallel updates to a DID Document
// Note: this does not work in a load balanced environment.
// for every updated DID, a mutex remains in this map, this should not be a problem
type keyedMutex struct {
	mutexes sync.Map
}

// Lock tries to lock a mutex for a certain key.
// It returns a function which can be used to unlock mutex for the key
func (m *keyedMutex) Lock(key string) func() {
	value, _ := m.mutexes.LoadOrStore(key, &sync.Mutex{})
	mtx := value.(*sync.Mutex)
	log.Logger().Tracef("aquiring lock for: %s", key)
	mtx.Lock()
	log.Logger().Tracef("lock aquired for: %s", key)

	// use this to unlock the mutex
	return func() {
		mtx.Unlock()
		log.Logger().Tracef("unlocked for: %s", key)
	}
}

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
	vcr             vcr.Finder
	// callSerializer can be used to (un)lock a resource such as a DID to prevent parallel updates
	callSerializer keyedMutex
}

// NewDidmanInstance creates a new didman instance with services set
func NewDidmanInstance(docResolver types.DocResolver, store types.Store, vdr types.VDR, vcr vcr.Finder, jsonldManager jsonld.JSONLD) Didman {
	return &didman{
		docResolver:     docResolver,
		serviceResolver: doc.NewServiceResolver(docResolver),
		store:           store,
		vdr:             vdr,
		vcr:             vcr,
		jsonldManager:   jsonldManager,
		callSerializer:  keyedMutex{},
	}
}

func (d *didman) Name() string {
	return ModuleName
}

func (d *didman) AddEndpoint(id did.DID, serviceType string, u url.URL) (*did.Service, error) {
	unlockFn := d.callSerializer.Lock(id.String())
	defer unlockFn()

	log.Logger().
		WithField(core.LogFieldDID, id.String()).
		WithField(core.LogFieldServiceType, serviceType).
		WithField(core.LogFieldServiceEndpoint, u.String()).
		Debug("Adding endpoint")
	service, err := d.addService(id, serviceType, u.String(), nil)
	if err == nil {
		log.Logger().
			WithField(core.LogFieldDID, id.String()).
			WithField(core.LogFieldServiceType, serviceType).
			WithField(core.LogFieldServiceEndpoint, u.String()).
			Info("Endpoint added")
	}
	return service, err
}

func (d *didman) DeleteEndpointsByType(id did.DID, serviceType string) error {
	unlockFn := d.callSerializer.Lock(id.String())
	defer unlockFn()

	doc, _, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return err
	}

	found := false
	for _, s := range doc.Service {
		if s.Type == serviceType {
			found = true
			if err = d.deleteService(s.ID); err != nil {
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
	unlockFn := d.callSerializer.Lock(id.String())
	defer unlockFn()

	log.Logger().
		WithField(core.LogFieldDID, id.String()).
		WithField(core.LogFieldServiceType, serviceType).
		WithField(core.LogFieldServiceEndpoint, endpoints).
		Debug("Adding compound service")
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
		log.Logger().
			WithField(core.LogFieldDID, id.String()).
			WithField(core.LogFieldServiceType, serviceType).
			WithField(core.LogFieldServiceEndpoint, endpoints).
			Info("Compound service added")
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
	id, err := did.ParseDIDURL(serviceID.String())
	if err != nil {
		return err
	}
	id.Fragment = ""

	unlockFn := d.callSerializer.Lock(id.String())
	defer unlockFn()

	return d.deleteService(serviceID)
}

// deleteService deletes the service without using the callSerializer locks
func (d *didman) deleteService(serviceID ssi.URI) error {
	log.Logger().
		WithField(core.LogFieldServiceID, serviceID.String()).
		Debug("Deleting service")
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
		log.Logger().
			WithField(core.LogFieldServiceID, serviceID.String()).
			Info("Service deleted")
	}
	return err
}

func (d *didman) UpdateContactInformation(id did.DID, information ContactInformation) (*ContactInformation, error) {
	unlockFn := d.callSerializer.Lock(id.String())
	defer unlockFn()

	log.Logger().
		WithField(core.LogFieldDID, id.String()).
		Debugf("Updating contact information service")

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
		log.Logger().
			WithField(core.LogFieldDID, id.String()).
			Info("Contact Information service added/updated")
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
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.OrganizationNamePath, Value: query, Type: vcr.Prefix},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}

	organizations, err := d.vcr.Search(ctx, searchTerms, false, nil)
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
		reader := jsonld.Reader{
			DocumentLoader:           d.jsonldManager.DocumentLoader(),
			AllowUndefinedProperties: true,
		}
		document, err := reader.Read(organizations[i])
		if err != nil {
			return nil, fmt.Errorf("failed to expand credential to JSON-LD: %w", err)
		}

		// guaranteed to contain values
		orgNames := document.ValueAt(jsonld.OrganizationNamePath)
		orgCities := document.ValueAt(jsonld.OrganizationCityPath)

		results[i] = OrganizationSearchResult{
			DIDDocument: *didDocuments[i],
			Organization: map[string]interface{}{
				"name": orgNames[0],
				"city": orgCities[0],
			},
		}
	}

	return results, nil
}

// resolveOrganizationDIDDocuments takes a slice of organization VCs and tries to resolve the corresponding DID document for each.
// If a DID document isn't found or it is deactivated the organization is filtered from the slice (reslicing the given slice) and omitted from the DID documents slice.
// If any other error occurs, it is returned.
func (d *didman) resolveOrganizationDIDDocuments(organizations []vc.VerifiableCredential) ([]*did.Document, []vc.VerifiableCredential, error) {
	didDocuments := make([]*did.Document, len(organizations))
	j := 0
	for i, organization := range organizations {
		document, organizationDID, err := d.resolveOrganizationDIDDocument(organization)
		if err != nil && !(errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrDeactivated)) {
			return nil, nil, err
		}
		if document == nil {
			// DID Document might be deactivated, so just log a warning and omit this entry from the search.
			log.Logger().
				WithError(err).
				WithField(core.LogFieldDID, organizationDID.String()).
				Warn("Unable to resolve organization DID Document")
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

func (d *didman) resolveOrganizationDIDDocument(organization vc.VerifiableCredential) (*did.Document, did.DID, error) {
	credentialSubject := make([]credential.BaseCredentialSubject, 0)
	err := organization.UnmarshalCredentialSubject(&credentialSubject)
	if err != nil {
		return nil, did.DID{}, fmt.Errorf("unable to get DID from organization credential: %w", err)
	}
	organizationDIDStr := credentialSubject[0].ID
	organizationDID, err := did.ParseDID(organizationDIDStr)
	if err != nil {
		return nil, did.DID{}, fmt.Errorf("unable to parse DID from organization credential: %w", err)
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
