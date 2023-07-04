package oidc4vci

import (
	"errors"
)

// ValidateCredentialDefinition validates the CredentialDefinition according to the VerifiableCredentialJSONLDFormat format
func ValidateCredentialDefinition(definition *CredentialDefinition, isOffer bool) error {
	if definition == nil {
		return errors.New("invalid credential_definition: missing")
	}
	if len(definition.Context) == 0 {
		return errors.New("invalid credential_definition: missing @context field")
	}
	if len(definition.Type) == 0 {
		return errors.New("invalid credential_definition: missing type field")
	}
	if definition.CredentialSubject != nil {
		if isOffer {
			return errors.New("invalid credential_definition: credentialSubject not allowed in offer")
		}
		// TODO: add credentialSubject validation.
	}
	return nil
}
