package iam

import (
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// MedicalMetadataScope is the scope for interacting with medical metadata (non-PII).
// TODO: We need to decide on these.
const MedicalMetadataScope = "medical-metadata"

// presentationDefinitionRegistry is a registry for presentation definitions.
type presentationDefinitionRegistry interface {
	// ByScope returns the presentation definition for the given scope.
	// If it can't map the scope to a presentation definition, nil is returned.
	ByScope(scope string) *pe.PresentationDefinition
}

type nutsPresentationDefinitionRegistry struct {
}

func (n nutsPresentationDefinitionRegistry) ByScope(scope string) *pe.PresentationDefinition {
	if scope != MedicalMetadataScope {
		return nil
	}
	return &pe.PresentationDefinition{
		Format: &pe.PresentationDefinitionClaimFormatDesignations{
			// TODO: Might have to support jwt_vc, but node doesn't support it yet.
			"ldp_vc": {
				"proof_type": []string{"JsonWebSignature2020"},
			},
		},
		Id: "pd_any_care_organization",
		InputDescriptors: []*pe.InputDescriptor{
			{
				Id: uuid.NewString(), // TODO: What should this be?
				Constraints: &pe.Constraints{
					Fields: []pe.Field{
						{
							Path: []string{"$.type"},
							Filter: &pe.Filter{
								Type:  "string",
								Const: pString("NutsOrganizationCredential"),
							},
						},
						{
							Path: []string{"$.credentialSubject.organization.name"},
							Filter: &pe.Filter{
								Type: "string",
							},
						},
						{
							Path: []string{"$.credentialSubject.organization.city"},
							Filter: &pe.Filter{
								Type: "string",
							},
						},
					},
				},
			},
		},
		Name:    "Care organization",
		Purpose: "Finding a care organization for authorizing access to medical metadata",
	}
}

func pString(val string) *string {
	return &val
}
