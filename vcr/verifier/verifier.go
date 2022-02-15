package verifier

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

var timeFunc = time.Now

const (
	maxSkew = 5 * time.Second
)

// Verifier defines the interface for verifying verifiable credentials.
type Verifier interface {
	// Verify checks credential on full correctness. It checks:
	// validity of the signature
	// if it has been revoked
	// if the issuer is registered as trusted
	Verify(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error
	// Validate checks the verifiable credential technical correctness
	Validate(credentialToVerify vc.VerifiableCredential, at *time.Time) error
}

// verifier implements the Verifier interface.
// It implements the generic methods for verifying verifiable credentials and verifiable presentations.
// It does not know anything about the semantics of a credential. It should support a wide range of types.
type verifier struct {
	keyResolver vdr.KeyResolver
}

// NewVerifier creates a new instance of the verifier. It needs a key resolver for validating signatures.
func NewVerifier(keyResolver vdr.KeyResolver) Verifier {
	return &verifier{keyResolver: keyResolver}
}

// validateAtTime is a helper method which checks if a credential is valid at a certain given time.
// If no validAt is provided, validAt is set to now.
// It returns nil if the credential is valid at the given time, otherwise it returns types.ErrInvalidPeriod
func (v *verifier) validateAtTime(credential vc.VerifiableCredential, validAt *time.Time) error {
	// if validAt is nil, use the result from timeFunc (usually now)
	at := timeFunc()
	if validAt != nil {
		at = *validAt
	}

	// check if issuanceDate is before validAt
	if credential.IssuanceDate.After(at.Add(maxSkew)) {
		return types.ErrInvalidPeriod
	}

	// check if expirationDate is after validAt
	if credential.ExpirationDate != nil && credential.ExpirationDate.Add(maxSkew).Before(at) {
		return types.ErrInvalidPeriod
	}
	return nil
}

// Validate implements the Proof Verification Algorithm: https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
func (v *verifier) Validate(credentialToVerify vc.VerifiableCredential, at *time.Time) error {
	ldProof := make([]proof.LDProof, 1)
	if err := credentialToVerify.UnmarshalProofValue(&ldProof); err != nil {
		return err
	}
	if len(ldProof) != 1 {
		return errors.New("credential must contain exactly 1 proof")
	}

	// check if verification method is of issuer (DID should be the same)
	vm := ldProof[0].VerificationMethod
	vm.Fragment = ""
	if vm != credentialToVerify.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := v.keyResolver.ResolveSigningKey(ldProof[0].VerificationMethod.String(), at)
	if err != nil {
		if at == nil {
			return fmt.Errorf("unable to resolve signing key: %w", err)
		}
		return fmt.Errorf("unable to resolve valid signing key at given time: %w", err)
	}

	signedDocument, err := proof.NewSignedDocument(credentialToVerify)
	if err != nil {
		return err
	}
	// Try first with the correct LDProof implementation
	if err = ldProof[0].Verify(signedDocument.DocumentWithoutProof(), signature.JsonWebSignature2020{}, pk); err != nil {
		// If this fails, try the legacy suite
		legacyProof := make([]proof.LegacyLDProof, 1)
		if err := credentialToVerify.UnmarshalProofValue(&legacyProof); err != nil {
			return err
		}
		if len(legacyProof) != 1 {
			// unable to parse the legacy proof, return the original error
			return err
		}
		credentialToVerify.Proof = nil
		return legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, pk)
	}
	return err

}

// Verify implements the verify interface.
// It currently checks if the credential has the required fields and values, if it is valid at the given time and optional the signature.
// TODO: check for revoked credentials.
// TODO: check if issuer-type combination is trusted
func (v verifier) Verify(credentialToVerify vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	// it must have valid content
	validator, _ := credential.FindValidatorAndBuilder(credentialToVerify)
	if err := validator.Validate(credentialToVerify); err != nil {
		return err
	}

	if err := v.validateAtTime(credentialToVerify, validAt); err != nil {
		return err
	}

	if checkSignature {
		return v.Validate(credentialToVerify, validAt)
	}

	return nil
}
