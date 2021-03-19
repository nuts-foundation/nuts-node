package templates

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

type ServiceTemplate struct {
	Name       string
	Controller ServiceTemplateParty `json:"controller"`
	Subject    ServiceTemplateParty `json:"subject"`
}

type ServiceTemplateParty struct {
	ConcreteServices []did.Service `json:"concreteServices"`
	CompoundServices []did.Service `json:"compoundServices"`
}

// ServiceTemplateApplier defines functions for applying/unapplying a service template.
type ServiceTemplateApplier struct {
	vdr types.VDR
}

// Apply creates services associated with the template on the controller and subject.
func (s ServiceTemplateApplier) Apply(controller did.DID, subject did.DID, template ServiceTemplate, properties map[string]string) error {
	logging.Log().Infof("Creating applying service template (template=%s, controller=%s, subject=%s)", template.Name, controller, subject)
	ctrlDID, ctrlDIDMetadata, err := s.vdr.Resolve(controller, nil)
	if err != nil {
		return fmt.Errorf("unable to resolve controller (did=%s): %w", controller, err)
	}
	var subjectDID *did.Document
	var subjectDIDMetadata *types.DocumentMetadata
	if subject.Equals(controller) {
		subjectDID = ctrlDID
		subjectDIDMetadata = ctrlDIDMetadata
	} else {
		subjectDID, subjectDIDMetadata, err = s.vdr.Resolve(subject, nil)
		if err != nil {
			return fmt.Errorf("unable to resolve subject (DID=%s): %w", subject, err)
		}
	}

	// Steps:
	// - Apply concrete endpoint services for controller
	// - Apply compound services for controller
	// - Apply concrete endpoint services for subject
	// - Apply compound services for subject

	ctrlDIDUpdated := s.createServices(ctrlDID, template.Controller.ConcreteServices, nil)
	ctrlDIDUpdated = ctrlDIDUpdated || s.createServices(ctrlDID, template.Controller.CompoundServices, template.Controller.ConcreteServices)
	subjectDIDUpdated := s.createServices(subjectDID, template.Subject.ConcreteServices, template.Controller.ConcreteServices)
	subjectDIDUpdated = subjectDIDUpdated || s.createServices(subjectDID, template.Subject.CompoundServices, append(template.Controller.ConcreteServices, template.Subject.ConcreteServices...))

	if ctrlDIDUpdated {
		if err := s.vdr.Update(ctrlDID.ID, ctrlDIDMetadata.Hash, *ctrlDID, ctrlDIDMetadata); err != nil {
			return fmt.Errorf("unable to update controller DID document (DID=%s): %w", ctrlDID.ID, err)
		}
	}
	if subjectDIDUpdated && !subject.Equals(controller) {
		if err := s.vdr.Update(subjectDID.ID, subjectDIDMetadata.Hash, *subjectDID, subjectDIDMetadata); err != nil {
			return fmt.Errorf("unable to update subject DID document (DID=%s): %w", ctrlDID.ID, err)
		}
	}
	return nil
}

func (s ServiceTemplateApplier) createServices(currentDocument *did.Document, servicesToApply, referencableServices []did.Service) bool {
	updated := false
	for _, serviceTemplate := range servicesToApply {
		if createOrUpdateService(currentDocument, currentDocument.Service, serviceTemplate) {
			updated = true
		}
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
	serviceEndpoint, isCompound := service.ServiceEndpoint.(map[string]interface{})
	if isCompound {

	}

	// TODO: Resolve references
	var serviceToUpdateOrCreate *did.Service
	for i, existingService := range currentDocument.Service {
		if existingService.Type == service.Type {
			if existingService.ServiceEndpoint == service.ServiceEndpoint {
				return false
			}
			// Service exists, update serviceEndpoint (only property that can change)
			serviceToUpdateOrCreate = &currentDocument.Service[i]
			break
		}
	}
	if serviceToUpdateOrCreate == nil {
		service.ID = currentDocument.ID.URI()
		service.ID.Fragment = uuid.New().String()
		logging.Log().Infof("Creating new DID service (ID=%s, type=%s)", service.ID, service.Type)
		serviceToUpdateOrCreate = &service
	} else {
		logging.Log().Infof("Updating endpoint of DID service (ID=%s, endpoint=%s)", serviceToUpdateOrCreate.ID, service.ServiceEndpoint)
	}



	existingService.ServiceEndpoint = service.ServiceEndpoint

		currentDocument.Service = append(currentDocument.Service, service)
	}
	return true
}

// Unapply disables services associated with the template for the given subject.
func (s ServiceTemplateApplier) Unapply(subject did.DID, template ServiceTemplate) error {
	panic("implement me")
}
