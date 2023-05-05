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
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

var timeFunc = time.Now

const (
	maxSkew = 5 * time.Second
)

// verifier implements the Verifier interface.
// It implements the generic methods for verifying verifiable credentials and verifiable presentations.
// It does not know anything about the semantics of a credential. It should support a wide range of types.
type verifier struct {
	docResolver   vdr.DocResolver
	keyResolver   vdr.KeyResolver
	jsonldManager jsonld.JSONLD
	store         Store
	trustConfig   *trust.Config
}

// VerificationError is used to describe a VC/VP verification failure.
type VerificationError struct {
	msg  string
	args []interface{}
}

// Is checks whether the given error is a VerificationError as well.
func (e VerificationError) Is(other error) bool {
	_, is := other.(VerificationError)
	return is
}

func newVerificationError(msg string, args ...interface{}) error {
	return VerificationError{msg: msg, args: args}
}

func toVerificationError(cause error) error {
	return VerificationError{msg: cause.Error()}
}

func (e VerificationError) Error() string {
	return fmt.Errorf("verification error: "+e.msg, e.args...).Error()
}

// NewVerifier creates a new instance of the verifier. It needs a key resolver for validating signatures.
func NewVerifier(store Store, docResolver vdr.DocResolver, keyResolver vdr.KeyResolver, jsonldManager jsonld.JSONLD, trustConfig *trust.Config) Verifier {
	return &verifier{store: store, docResolver: docResolver, keyResolver: keyResolver, jsonldManager: jsonldManager, trustConfig: trustConfig}
}

// validateAtTime is a helper method which checks if a credential/presentation is valid at a certain given time.
// If no validAt is provided, validAt is set to now.
func (v *verifier) validateAtTime(issuanceDate time.Time, expirationDate *time.Time, validAt *time.Time) bool {
	// if validAt is nil, use the result from timeFunc (usually now)
	at := timeFunc()
	if validAt != nil {
		at = *validAt
	}

	// check if issuanceDate is before validAt
	if issuanceDate.After(at.Add(maxSkew)) {
		return false
	}

	// check if expirationDate is after validAt
	if expirationDate != nil && expirationDate.Add(maxSkew).Before(at) {
		return false
	}
	return true
}

// Validate implements the Proof Verification Algorithm: https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
func (v *verifier) Validate(credentialToVerify vc.VerifiableCredential, at *time.Time) error {
	err := v.validateType(credentialToVerify)
	if err != nil {
		return err
	}

	signedDocument, err := proof.NewSignedDocument(credentialToVerify)
	if err != nil {
		return fmt.Errorf("unable to build signed document from verifiable credential: %w", err)
	}

	ldProof := proof.LDProof{}
	if err := signedDocument.UnmarshalProofValue(&ldProof); err != nil {
		return fmt.Errorf("unable to extract ldproof from signed document: %w", err)
	}

	verificationMethod := ldProof.VerificationMethod.String()
	verificationMethodIssuer := strings.Split(verificationMethod, "#")[0]
	if verificationMethodIssuer == "" || verificationMethodIssuer != credentialToVerify.Issuer.String() {
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
	return ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: v.jsonldManager.DocumentLoader()}, pk)
}

// Verify implements the verify interface.
// It currently checks if the credential has the required fields and values, if it is valid at the given time and optional the signature.
func (v verifier) Verify(credentialToVerify vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	// it must have valid content
	validator := credential.FindValidator(credentialToVerify)
	if err := validator.Validate(credentialToVerify); err != nil {
		return err
	}

	// Check revocation status
	revoked, err := v.IsRevoked(*credentialToVerify.ID)
	if err != nil {
		return err
	}
	if revoked {
		return types.ErrRevoked
	}

	// Check trust status
	if !allowUntrusted {
		for _, t := range credentialToVerify.Type {
			// Don't need to check type "VerifiableCredential"
			if t.String() == verifiableCredentialType {
				continue
			}
			if !v.trustConfig.IsTrusted(t, credentialToVerify.Issuer) {
				return types.ErrUntrusted
			}
		}
	}

	// Check issuance/expiration time
	if !v.validateAtTime(credentialToVerify.IssuanceDate, credentialToVerify.ExpirationDate, validAt) {
		return types.ErrCredentialNotValidAtTime
	}

	// Check signature
	if checkSignature {
		issuerDID, _ := did.ParseDID(credentialToVerify.Issuer.String())
		_, _, err = v.docResolver.Resolve(*issuerDID, &vdr.ResolveMetadata{ResolveTime: validAt, AllowDeactivated: false})
		if err != nil {
			return fmt.Errorf("could not validate issuer: %w", err)
		}

		return v.Validate(credentialToVerify, validAt)
	}

	return nil
}

func (v *verifier) IsRevoked(credentialID ssi.URI) (bool, error) {
	_, err := v.store.GetRevocations(credentialID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (v *verifier) GetRevocation(credentialID ssi.URI) (*credential.Revocation, error) {
	revocation, err := v.store.GetRevocations(credentialID)
	if err != nil {
		return nil, err
	}

	// GetRevocations returns ErrNotFound for len == 0
	return revocation[0], nil
}

func (v *verifier) RegisterRevocation(revocation credential.Revocation) error {
	asBytes, _ := json.Marshal(revocation)
	document := proof.SignedDocument{}
	if err := json.Unmarshal(asBytes, &document); err != nil {
		return err
	}

	if err := credential.ValidateRevocation(revocation); err != nil {
		return err
	}

	// Revocation issuer must be the same as credential issuer
	// Subject contains the credential ID
	subject := revocation.Subject.String()
	// The first part before the # is the credentialIssuer
	subjectIssuer := strings.Split(subject, "#")[0]
	// Check if the revocation issuer is the same as the credential issuer
	if subjectIssuer != revocation.Issuer.String() {
		return errors.New("issuer of revocation is not the same as issuer of credential")
	}

	// Check if the key used to sign the revocation belongs to the revocation issuer
	vm := revocation.Proof.VerificationMethod.String()
	vmIssuer := strings.Split(vm, "#")[0]
	if vmIssuer != revocation.Issuer.String() {
		return errors.New("verificationMethod should owned by the issuer")
	}

	pk, err := v.keyResolver.ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date)
	if err != nil {
		return fmt.Errorf("unable to resolve key for revocation: %w", err)
	}

	ldProof := proof.LDProof{}
	if err := document.UnmarshalProofValue(&ldProof); err != nil {
		return err
	}
	err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: v.jsonldManager.DocumentLoader()}, pk)
	if err != nil {
		return fmt.Errorf("unable to verify revocation signature: %w", err)
	}

	if err := v.store.StoreRevocation(revocation); err != nil {
		return fmt.Errorf("unable to store revocation: %w", err)
	}
	return nil
}

func (v verifier) VerifyVP(vp vc.VerifiablePresentation, verifyVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error) {
	return v.doVerifyVP(&v, vp, verifyVCs, validAt)
}

// doVerifyVP delegates VC verification to the supplied Verifier, to aid unit testing.
func (v verifier) doVerifyVP(vcVerifier Verifier, vp vc.VerifiablePresentation, verifyVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error) {
	// Multiple proofs might be supported in the future, when there's an actual use case.
	if len(vp.Proof) != 1 {
		return nil, newVerificationError("exactly 1 proof is expected")
	}
	// Make sure the proofs are LD-proofs
	var ldProofs []proof.LDProof
	err := vp.UnmarshalProofValue(&ldProofs)
	if err != nil {
		return nil, newVerificationError("unsupported proof type: %w", err)
	}
	ldProof := ldProofs[0]

	// Validate signing time
	if !v.validateAtTime(ldProof.Created, ldProof.Expires, validAt) {
		return nil, toVerificationError(types.ErrPresentationNotValidAtTime)
	}

	// Validate signature
	signingKey, err := v.keyResolver.ResolveSigningKey(ldProof.VerificationMethod.String(), validAt)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve valid signing key: %w", err)
	}
	signedDocument, err := proof.NewSignedDocument(vp)
	if err != nil {
		return nil, newVerificationError("invalid LD-JSON document: %w", err)
	}
	err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: v.jsonldManager.DocumentLoader()}, signingKey)
	if err != nil {
		return nil, newVerificationError("invalid signature: %w", err)
	}

	if verifyVCs {
		for _, current := range vp.VerifiableCredential {
			err := vcVerifier.Verify(current, false, true, validAt)
			if err != nil {
				return nil, newVerificationError("invalid VC (id=%s): %w", current.ID, err)
			}
		}
	}

	return vp.VerifiableCredential, nil
}

func (v *verifier) validateType(credential vc.VerifiableCredential) error {
	// VCs must contain 2 types: "VerifiableCredential" and specific type
	if len(credential.Type) > 2 {
		return errors.New("verifiable credential must list at most 2 types")
	}
	// "VerifiableCredential" should be one of the types
	for _, curr := range credential.Type {
		if curr == vc.VerifiableCredentialTypeV1URI() {
			return nil
		}
	}
	return fmt.Errorf("verifiable credential does not list '%s' as type", vc.VerifiableCredentialTypeV1URI())
}
