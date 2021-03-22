package templates

import (
	"github.com/nuts-foundation/go-did"
)

type Definition interface {
	Name() string
	Interpolate(parameters map[string]string) (ServiceTemplate, error)
}

type ServiceTemplate struct {
	Controller ServiceTemplateParty
	Subject    ServiceTemplateParty
}

type ServiceTemplateParty struct {
	ConcreteServices []did.Service `json:"concreteServices"`
	CompoundServices []did.Service `json:"compoundServices"`
}
