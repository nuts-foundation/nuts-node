package oidc4vci

import (
	"errors"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
)

// CredentialTypesMatchDefinition validates that credential matches VerifiableCredentialJSONLDFormat's credential_definition
func CredentialTypesMatchDefinition(reader jsonld.Reader, credential vc.VerifiableCredential, credentialDefinition map[string]interface{}) error {
	// In json-LD format the types need to be compared in expanded format
	document, err := reader.Read(credentialDefinition)
	if err != nil {
		return fmt.Errorf("invalid credential_definition: %w", err)
	}
	// TODO: can credentialDefinition contain invalid values that makes this panic?
	expectedTypes := document.ValueAt(jsonld.NewPath("@type"))

	document, err = reader.Read(credential)
	if err != nil {
		return fmt.Errorf("invalid credential: %w", err)
	}
	receivedTypes := document.ValueAt(jsonld.NewPath("@type"))

	if !equal(expectedTypes, receivedTypes) {
		return errors.New("credential Type do not match")
	}

	return nil
}

// equal returns true if both slices have the same values in the same order.
// Note: JSON arrays are ordered, JSON object elements are not.
func equal(a, b []jsonld.Scalar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
