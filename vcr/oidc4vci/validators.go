package oidc4vci

import (
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
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

// ValidateDefinitionWithCredential confirms that the vc.VerifiableCredential is defined by the CredentialDefinition.
// CredentialDefinition is assumed to be valid, see ValidateCredentialDefinition.
func ValidateDefinitionWithCredential(credential vc.VerifiableCredential, definition CredentialDefinition) error {
	// compare contexts. The credential may contain extra contexts for signatures or proofs
	if len(credential.Context) < len(definition.Context) || !isSubset(credential.Context, definition.Context) {
		return errors.New("credential does not match credential_definition: context mismatch")
	}

	// compare types. fails when definition.Type contains duplicates
	if len(credential.Type) != len(definition.Type) || !isSubset(credential.Type, definition.Type) {
		return errors.New("credential does not match credential_definition: type mismatch")
	}

	// TODO: compare credentialSubject

	return nil
}

// isSubset is true if all elements of subset exist in set. If subset is empty it returns false.
func isSubset(set, subset []ssi.URI) bool {
	if len(subset) == 0 {
		return false
	}
	for _, el1 := range subset {
		found := false
		for _, el2 := range set {
			if el2.String() == el1.String() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
