/*
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

package vdr

import (
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-node/network/transport"

	"github.com/lestrrat-go/jwx/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// NetworkDocumentValidator creates a DID Document validator that checks for inconsistencies in the DID Document:
// - validate it according to the W3C DID Core Data Model specification
// - validate it according to the Nuts DID Method specification:
//   - it checks validationMethods for the following conditions:
//   - every validationMethod id must have a fragment
//   - every validationMethod id should have the DID prefix
//   - every validationMethod id must be unique
//   - it checks services for the following conditions:
//   - every service id must have a fragment
//   - every service id should have the DID prefix
//   - every service id must be unique
//   - every service type must be unique
func NetworkDocumentValidator() did.Validator {
	return &did.MultiValidator{Validators: []did.Validator{
		did.W3CSpecValidator{},
		verificationMethodValidator{},
		basicServiceValidator{},
	}}
}

// ManagedDocumentValidator extends NetworkDocumentValidator with extra safety checks to be performed on DID documents managed by this node before they are published on the network.
func ManagedDocumentValidator(serviceResolver didservice.ServiceResolver) did.Validator {
	return &did.MultiValidator{Validators: []did.Validator{
		NetworkDocumentValidator(),
		managedServiceValidator{serviceResolver},
	}}
}

// verificationMethodValidator validates the Verification Methods of a Nuts DID Document.
type verificationMethodValidator struct{}

func (v verificationMethodValidator) Validate(document did.Document) error {
	knownKeyIds := make(map[string]bool, 0)
	for _, method := range document.VerificationMethod {
		if err := verifyDocumentEntryID(document.ID, method.ID.URI(), knownKeyIds); err != nil {
			return fmt.Errorf("invalid verificationMethod: %w", err)
		}
		if err := v.verifyThumbprint(method); err != nil {
			return fmt.Errorf("invalid verificationMethod: %w", err)
		}
	}
	return nil
}

func (v verificationMethodValidator) verifyThumbprint(method *did.VerificationMethod) error {
	keyAsJWK, err := method.JWK()
	if err != nil {
		return fmt.Errorf("unable to get JWK: %w", err)
	}
	_ = jwk.AssignKeyID(keyAsJWK)
	if keyAsJWK.KeyID() != method.ID.Fragment {
		return errors.New("key thumbprint does not match ID")
	}
	return nil
}

type InvalidServiceError struct {
	Cause error
}

func (e InvalidServiceError) Error() string {
	return "invalid service: " + e.Cause.Error()
}

func (e InvalidServiceError) Unwrap() error {
	return e.Cause
}

// basicServiceValidator validates service.ID and service.Type of the Services of a DID Document.
// To be used on DID documents received through the network.
type basicServiceValidator struct{}

func (b basicServiceValidator) Validate(document did.Document) error {
	knownServiceIDs := make(map[string]bool, 0)
	knownServiceTypes := make(map[string]bool, 0)
	for _, service := range document.Service {
		// service.id
		if err := verifyDocumentEntryID(document.ID, service.ID, knownServiceIDs); err != nil {
			return InvalidServiceError{err}
		}

		// service.type
		if knownServiceTypes[service.Type] {
			// RFC006 §4: A DID Document MAY NOT contain more than one service with the same type.
			return InvalidServiceError{types.ErrDuplicateService}
		}
		knownServiceTypes[service.Type] = true
	}
	return nil
}

// managedServiceValidator only validates the Service.ServiceEndpoint in a DID document.
// Correctness of a service endpoint is the responsibility of the controller. Services on DID documents received through the network should therefor not be validated.
// This validator is exists to guarantee that the service endpoints are at least valid at time of publication.
// Should be used together with basicServiceValidator for full service validation.
type managedServiceValidator struct {
	serviceResolver didservice.ServiceResolver
}

func (m managedServiceValidator) Validate(document did.Document) error {
	// normalize services for consistent type checking.
	// TODO: this should probably happen somewhere else
	bytes, err := document.MarshalJSON()
	if err != nil {
		return InvalidServiceError{err}
	}
	if err = document.UnmarshalJSON(bytes); err != nil {
		return InvalidServiceError{err}
	}

	// make sure that it resolves when if it's a reference
	var resolvedEndpoint any
	// Cache resolved DID documents because most of the time all (compound) services will refer to the same DID document in all service references.
	cache := make(map[string]*did.Document, 1)
	cache[document.ID.String()] = &document // add the updated document to the cache in case it contains self-references
	for _, service := range document.Service {
		switch se := service.ServiceEndpoint.(type) {
		case map[string]interface{}:
			knownKeys := make(map[string]bool, len(se))
			resolvedCompoundEndpoint := make(map[string]any, len(se)) // don't know if returned type is string or another map
			for name, endpoint := range se {
				if _, exists := knownKeys[name]; exists {
					err = errors.New("duplicate service key in compound service")
					break
				}
				knownKeys[name] = true
				// resolve by treating endpoints as individual services
				if resolvedEndpoint, err = m.resolveOrReturnEndpoint(did.Service{ServiceEndpoint: endpoint}, cache); err != nil {
					break
				}
				resolvedCompoundEndpoint[name] = resolvedEndpoint
			}
			resolvedEndpoint = resolvedCompoundEndpoint
		case []interface{}:
			// RFC006 only allows maps or string, not sets.
			// Since service is not a map, and go-did normalizes everything to plurals, assume this is a string.
			resolvedEndpoint, err = m.resolveOrReturnEndpoint(service, cache)
		default:
			err = errors.New("invalid service format")
		}
		if err != nil {
			return InvalidServiceError{err}
		}

		// specific service.Type need additional validation
		resolvedService := did.Service{
			ID:              service.ID,
			Type:            service.Type,
			ServiceEndpoint: resolvedEndpoint,
		}
		if err = serviceTypeValidation(resolvedService); err != nil {
			return InvalidServiceError{fmt.Errorf("%s: %w", service.Type, err)}
		}
	}
	return nil
}

func (m managedServiceValidator) resolveOrReturnEndpoint(service did.Service, cache map[string]*did.Document) (any, error) {
	var serviceEndpoint string
	if err := service.UnmarshalServiceEndpoint(&serviceEndpoint); err != nil {
		return nil, errors.New("invalid service format")
	}
	// make sure that it resolves if it is a reference
	if didservice.IsServiceReference(serviceEndpoint) {
		serviceURI, err := ssi.ParseURI(serviceEndpoint)
		if err != nil {
			return nil, err
		}
		if err = didservice.ValidateServiceReference(*serviceURI); err != nil {
			return nil, err
		}
		resolvedService, err := m.serviceResolver.ResolveEx(*serviceURI, 0, didservice.DefaultMaxServiceReferenceDepth, cache)
		if err != nil {
			return nil, err
		}
		return resolvedService.ServiceEndpoint, nil
	}
	return serviceEndpoint, nil
}

func serviceTypeValidation(service did.Service) error {
	switch service.Type {
	case "NutsComm":
		return validateNutsCommEndpoint(service)
	case "node-contact-info":
		return validateNodeContactInfo(service)
	default:
		// no extra type-based validation
		return nil
	}
}

func validateNutsCommEndpoint(service did.Service) error {
	// RFC015 $3.2: NutsComm rules
	var ncEndpoint transport.NutsCommURL
	if err := service.UnmarshalServiceEndpoint(&ncEndpoint); err != nil {
		return err
	}
	return nil
}

func validateNodeContactInfo(service did.Service) error {
	// RFC006 §4.2 Contact information
	var endpointMap map[string]string
	if err := service.UnmarshalServiceEndpoint(&endpointMap); err != nil {
		return errors.New("not a map")
	}
	if _, ok := endpointMap["email"]; !ok {
		return errors.New("missing email")
	}
	return nil
}

func verifyDocumentEntryID(owner did.DID, entryID ssi.URI, knownIDs map[string]bool) error {
	// Check the ID has a fragment
	if entryID.Fragment == "" {
		return errors.New("ID must have a fragment")
	}
	// Check if this ID was part of a previous entry
	entryIDStr := entryID.String()
	if knownIDs[entryIDStr] {
		return errors.New("ID must be unique")
	}
	entryID.Fragment = ""
	if owner.String() != entryID.String() {
		return errors.New("ID must have document prefix")
	}
	knownIDs[entryIDStr] = true
	return nil
}
