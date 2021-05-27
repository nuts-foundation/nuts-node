package vdr

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// CreateDocumentValidator creates a DID Document validator that checks for inconsistencies in the the DID Document:
// - validate it according to the W3C DID Core Data Model specification
// - validate is according to the Nuts DID Method specification:
//  - it checks validationMethods for the following conditions:
//   - every validationMethod id must have a fragment
//   - every validationMethod id should have the DID prefix
//   - every validationMethod id must be unique
//  - it checks services for the following conditions:
//   - every service id must have a fragment
//   - every service id should have the DID prefix
//   - every service id must be unique
func CreateDocumentValidator() did.Validator {
	return &did.MultiValidator{Validators: []did.Validator{
		did.W3CSpecValidator{},
		verificationMethodValidator{},
		serviceValidator{},
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

// serviceValidator validates the Services of a Nuts DID Document.
type serviceValidator struct{}

func (s serviceValidator) Validate(document did.Document) error {
	knownServiceIDs := make(map[string]bool, 0)
	knownServiceTypes := make(map[string]bool, 0)
	for _, method := range document.Service {
		var err error
		if err = verifyDocumentEntryID(document.ID, method.ID, knownServiceIDs); err == nil {
			if knownServiceTypes[method.Type] {
				err = types.ErrDuplicateService
			}
		}
		if err != nil {
			return fmt.Errorf("invalid service: %w", err)
		}
		knownServiceTypes[method.Type] = true
	}
	return nil
}

func verifyDocumentEntryID(owner did.DID, entryID ssi.URI, knownIDs map[string]bool) error {
	// Check theID has a fragment
	if len(entryID.Fragment) == 0 {
		return fmt.Errorf("ID must have a fragment")
	}
	// Check if this ID was part of a previous entry
	entryIDStr := entryID.String()
	if knownIDs[entryIDStr] {
		return fmt.Errorf("ID must be unique")
	}
	entryID.Fragment = ""
	if owner.String() != entryID.String() {
		return fmt.Errorf("ID must have document prefix")
	}
	knownIDs[entryIDStr] = true
	return nil
}
