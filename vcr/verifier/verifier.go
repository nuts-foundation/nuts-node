/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/piprate/json-gold/ld"
	"time"
)

var timeFunc = time.Now

const (
	maxSkew = 5 * time.Second
)

// verifier implements the Verifier interface.
// It implements the generic methods for verifying verifiable credentials and verifiable presentations.
// It does not know anything about the semantics of a credential. It should support a wide range of types.
type verifier struct {
	keyResolver   vdr.KeyResolver
	contextLoader ld.DocumentLoader
	store         Store
}

// NewVerifier creates a new instance of the verifier. It needs a key resolver for validating signatures.
func NewVerifier(store Store, keyResolver vdr.KeyResolver, contextLoader ld.DocumentLoader) Verifier {
	return &verifier{store: store, keyResolver: keyResolver, contextLoader: contextLoader}
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
	signedDocument, err := proof.NewSignedDocument(credentialToVerify)
	if err != nil {
		return fmt.Errorf("unable to build signed document from verifiable credential: %w", err)
	}

	ldProof := proof.LDProof{}
	if err := signedDocument.UnmarshalProofValue(&ldProof); err != nil {
		return fmt.Errorf("unable to extract ldproof from signed document: %w", err)
	}

	verificationMethod := ldProof.VerificationMethod
	verificationMethod.Fragment = ""
	if verificationMethod.String() == "" || verificationMethod != credentialToVerify.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := v.keyResolver.ResolveSigningKey(ldProof.VerificationMethod.String(), at)
	if err != nil {
		if at == nil {
			return fmt.Errorf("unable to resolve signing key: %w", err)
		}
		return fmt.Errorf("unable to resolve valid signing key at given time: %w", err)
	}

	// Try first with the correct LDProof implementation
	if err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: v.contextLoader}, pk); err != nil {
		// If this fails, try the legacy suite:
		legacyProof := proof.LegacyLDProof{}
		if err := signedDocument.UnmarshalProofValue(&legacyProof); err != nil {
			return err
		}
		return legacyProof.Verify(signedDocument.DocumentWithoutProof(), signature.LegacyNutsSuite{}, pk)
	}
	return err

}

// Verify implements the verify interface.
// It currently checks if the credential has the required fields and values, if it is valid at the given time and optional the signature.
// For the v2 api to be complete implement the following TODOs:
// TODO: check if issuer-type combination is trusted
func (v verifier) Verify(credentialToVerify vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	// it must have valid content
	validator, _ := credential.FindValidatorAndBuilder(credentialToVerify)
	if err := validator.Validate(credentialToVerify); err != nil {
		return err
	}

	revoked, err := v.IsRevoked(*credentialToVerify.ID)
	if revoked {
		return errors.New("credential is revoked")
	}
	if err != nil {
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

func (v *verifier) IsRevoked(credentialID ssi.URI) (bool, error) {
	_, err := v.store.GetRevocation(credentialID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (v *verifier) CheckAndStoreRevocation(document proof.SignedDocument) error {
	asBytes, err := json.Marshal(document)
	revocation := credential.Revocation{}
	if err := json.Unmarshal(asBytes, &revocation); err != nil {
		return err
	}

	if err := credential.ValidateRevocation(revocation); err != nil {
		return err
	}

	// issuer must be the same as vc issuer
	subject := revocation.Subject
	subject.Fragment = ""
	if subject != revocation.Issuer {
		return errors.New("issuer of revocation is not the same as issuer of credential")
	}

	vmWithoutFragment := revocation.Proof.VerificationMethod
	vmWithoutFragment.Fragment = ""
	if vmWithoutFragment != revocation.Issuer {
		return errors.New("verificationMethod should owned by the issuer")
	}

	pk, err := v.keyResolver.ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date)
	if err != nil {
		return fmt.Errorf("unable to resolve key for revocation: %w", err)
	}

	// FIXME: use a cached contextLoader
	contextLoader, err := signature.NewContextLoader(true)
	if err != nil {
		return fmt.Errorf("unable to check and store revocation: %w", err)
	}

	ldProof := proof.LDProof{}
	if err := document.UnmarshalProofValue(&ldProof); err != nil {
		return err
	}
	err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
	if err != nil {
		return fmt.Errorf("unable to verify revocation signature: %w", err)
	}

	if err := v.store.StoreRevocation(revocation); err != nil {
		return fmt.Errorf("unable to store revocation: %w", err)
	}
	return nil
}
