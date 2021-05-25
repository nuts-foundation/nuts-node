package vdr

import (
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
)

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
	publicKey, err := method.PublicKey()
	if err != nil {
		return fmt.Errorf("unable to get public key: %w", err)
	}
	kid, err := doc.DIDKIDNamingFunc(publicKey)
	if err != nil {
		return fmt.Errorf("unable to generate key name: %w", err)
	}
	if kid != method.ID.String() {
		return errors.New("verificationMethod ID is invalid")
	}
	return nil
}

// serviceValidator validates the Services of a Nuts DID Document.
type serviceValidator struct{}

func (s serviceValidator) Validate(document did.Document) error {
	knownServiceIDs := make(map[string]bool, 0)
	knownServiceTypes := make(map[string]bool, 0)
	for _, method := range document.Service {
		if err := verifyDocumentEntryID(document.ID, method.ID, knownServiceIDs); err != nil {
			return fmt.Errorf("invalid service: %w", err)
		}
		if knownServiceTypes[method.Type] {
			return errors.New("invalid service: duplicate service type")
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
	entryIDAsDID, err := did.ParseDID(entryIDStr)
	if err != nil {
		// Shouldn't happen
		return err
	}
	entryIDAsDID.Fragment = ""
	if !owner.Equals(*entryIDAsDID) {
		return fmt.Errorf("ID must have document prefix")
	}
	knownIDs[entryIDStr] = true
	return nil
}
