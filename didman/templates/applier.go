package templates

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	errors2 "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"reflect"
)

var ErrInvalidServiceTemplateParameters = errors.New("invalid service template parameters")

// ServiceTemplateApplier defines functions for applying/unapplying a service template.
type ServiceTemplateApplier struct {
	VDR types.VDR
}

// Apply creates services associated with the template on the controller and subject.
func (s ServiceTemplateApplier) Apply(controller did.DID, subject did.DID, templateDefinition Definition, parameters map[string]string) error {
	logging.Log().Infof("Applying service template (template=%s, controller=%s, subject=%s)", templateDefinition.Name(), controller, subject)
	// TODO: Validate that all services resolve to other services within the template. Otherwise the result isn't deterministic (referencing existing services)
	// Resolve controller
	ctrlDID, ctrlDIDMetadata, err := s.VDR.Resolve(controller, nil)
	if err != nil {
		return fmt.Errorf("unable to resolve controller (did=%s): %w", controller, err)
	}
	// Resolve subject
	var subjectDID *did.Document
	var subjectDIDMetadata *types.DocumentMetadata
	if subject.Equals(controller) {
		subjectDID = ctrlDID
		subjectDIDMetadata = ctrlDIDMetadata
	} else {
		subjectDID, subjectDIDMetadata, err = s.VDR.Resolve(subject, nil)
		if err != nil {
			return fmt.Errorf("unable to resolve subject (DID=%s): %w", subject, err)
		}
	}
	// Make sure controller is an actual controller of the subject
	// TODO: Move IsController() to go-did
	isController := false
	for _, curr := range subjectDID.Controller {
		if curr.Equals(controller) {
			isController = true
			break
		}
	}
	if !isController {
		return errors.New("given controller DID is not an actual controller of the subject")
	}

	// Interpolate template definition to get the actual service template to apply
	template, err := templateDefinition.Interpolate(parameters)
	if err != nil {
		return errors2.Wrap(ErrInvalidServiceTemplateParameters, err.Error())
	}

	// Steps:
	// - Apply concrete endpoint services for controller
	// - Apply compound services for controller
	// - Apply concrete endpoint services for subject
	// - Apply compound services for subject
	ctrlDIDUpdated := s.createServices(ctrlDID, template.Controller.ConcreteServices, nil)
	ctrlDIDUpdated = ctrlDIDUpdated || s.createServices(ctrlDID, template.Controller.CompoundServices, template.Controller.ConcreteServices)
	subjectDIDUpdated := s.createServices(subjectDID, template.Subject.ConcreteServices, template.Controller.ConcreteServices)
	// TODO: When the concrete endpoint is present in both controller and subject DID documents, it takes the one from the subject, which is unexpected.
	subjectDIDUpdated = subjectDIDUpdated || s.createServices(subjectDID, template.Subject.CompoundServices, append(template.Controller.ConcreteServices, template.Subject.ConcreteServices...))
	if ctrlDIDUpdated {
		if err := s.VDR.Update(ctrlDID.ID, ctrlDIDMetadata.Hash, *ctrlDID, ctrlDIDMetadata); err != nil {
			return fmt.Errorf("unable to update controller DID document (DID=%s): %w", ctrlDID.ID, err)
		}
	}
	// If the caller passed the same DID for both controller and subject, we don't need to update the subject DID document
	// because we already updated the controller DID document.
	if subjectDIDUpdated && !subject.Equals(controller) {
		if err := s.VDR.Update(subjectDID.ID, subjectDIDMetadata.Hash, *subjectDID, subjectDIDMetadata); err != nil {
			return fmt.Errorf("unable to update subject DID document (DID=%s): %w", ctrlDID.ID, err)
		}
	}
	return nil
}

func (s ServiceTemplateApplier) createServices(currentDocument *did.Document, servicesToApply, referencableServices []did.Service) bool {
	updated := false
	for _, serviceTemplate := range servicesToApply {
		updated = updated || createOrUpdateService(currentDocument, currentDocument.Service, serviceTemplate)
	}
	return updated
}

// createOrUpdateService checks if the specified service exists for the DID document and creates/updates it:
// - if it exists and is 100% equal, it does nothing
// - if it exists but differs, it is updated
// - if it doesn't exist, it is created
// The function returns true when the service was created or updated, false if nothing was done
// (because the DID document already was up-to-date).
func createOrUpdateService(currentDocument *did.Document, referencableServices []did.Service, service did.Service) bool {
	// If it is a compound service, resolve the references
	serviceEndpoint, isCompound := service.ServiceEndpoint.(map[string]interface{})
	if isCompound {
		service.ID = did.URI{}
		for referencedType := range serviceEndpoint {
			referencedService := findServiceWithType(referencableServices, referencedType)
			if referencedService == nil {
				logrus.Errorf("concrete service can't be resolved (DID=%s, compound service type=%s)", currentDocument.ID, service.Type)
				return false
			}
			serviceEndpoint[referencedType] = referencedService.ID
		}
	}

	var serviceToUpdateOrCreate *did.Service
	for i, existingService := range currentDocument.Service {
		if existingService.Type == service.Type {
			if reflect.DeepEqual(existingService.ServiceEndpoint, service.ServiceEndpoint) {
				return false
			}
			// Service exists, update serviceEndpoint (only property that can change)
			serviceToUpdateOrCreate = &currentDocument.Service[i]
			break
		}
	}
	if serviceToUpdateOrCreate == nil {
		serviceToUpdateOrCreate = &did.Service{}
		*serviceToUpdateOrCreate = service
		serviceToUpdateOrCreate.ID = currentDocument.ID.URI()
		serviceToUpdateOrCreate.ID.Fragment = uuid.New().String()
		logging.Log().Infof("Creating new DID service (ID=%s, type=%s)", serviceToUpdateOrCreate.ID, serviceToUpdateOrCreate.Type)
		currentDocument.Service = append(currentDocument.Service, *serviceToUpdateOrCreate)
	} else {
		serviceToUpdateOrCreate.ServiceEndpoint = service.ServiceEndpoint
		logging.Log().Infof("Updating endpoint of DID service (ID=%s, endpoint=%s)", serviceToUpdateOrCreate.ID, serviceToUpdateOrCreate.ServiceEndpoint)
	}
	return true
}

func findServiceWithType(services []did.Service, referencedType string) *did.Service {
	for _, svc := range services {
		if svc.Type == referencedType {
			return &svc
		}
	}
	return nil
}

// Unapply disables services associated with the template for the given subject.
func (s ServiceTemplateApplier) Unapply(subject did.DID, templateDefinition Definition) error {
	panic("implement me")
}
