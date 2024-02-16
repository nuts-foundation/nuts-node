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
	"github.com/nuts-foundation/nuts-node/vcr/statuslist"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var timeFunc = time.Now

const (
	maxSkew = 5 * time.Second
)

var errVerificationMethodNotOfIssuer = errors.New("verification method is not of issuer")

// verifier implements the Verifier interface.
// It implements the generic methods for verifying verifiable credentials and verifiable presentations.
// It does not know anything about the semantics of a credential. It should support a wide range of types.
type verifier struct {
	didResolver   resolver.DIDResolver
	keyResolver   resolver.KeyResolver
	jsonldManager jsonld.JSONLD
	store         Store
	trustConfig   *trust.Config
	signatureVerifier
	credentialStatus *statuslist.credentialStatus
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
func NewVerifier(store Store, didResolver resolver.DIDResolver, keyResolver resolver.KeyResolver, jsonldManager jsonld.JSONLD, trustConfig *trust.Config, client core.HTTPRequestDoer) Verifier {
	v := &verifier{store: store, didResolver: didResolver, keyResolver: keyResolver, jsonldManager: jsonldManager, trustConfig: trustConfig}
	v.signatureVerifier = signatureVerifier{
		keyResolver:   keyResolver,
		jsonldManager: jsonldManager,
	}
	v.credentialStatus = &statuslist.credentialStatus{
		client:          client,
		verifySignature: v.signatureVerifier.VerifySignature,
	}
	return v
}

// Verify implements the verify interface.
// It currently checks if the credential has the required fields and values, if it is valid at the given time and optional the signature.
func (v verifier) Verify(credentialToVerify vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	// it must have valid content
	validator := credential.FindValidator(credentialToVerify)
	if err := validator.Validate(credentialToVerify); err != nil {
		return err
	}
	// We only accept VCs with at most 2 types: "VerifiableCredential" and a specific type
	// The Validate above already checks "VerifiableCredential" is one of them
	// This is a custom requirement
	if len(credentialToVerify.Type) > 2 {
		return errors.New("verifiable credential must list at most 2 types")
	}

	// Check revocation status
	if credentialToVerify.ID != nil {
		revoked, err := v.IsRevoked(*credentialToVerify.ID)
		if err != nil {
			return err
		}
		if revoked {
			return types.ErrRevoked
		}

	}

	// Check the credentialStatus if the credential is revoked
	err := v.credentialStatus.verify(credentialToVerify)
	if err != nil {
		// soft fail, only return an error when revocation is confirmed and log everything else
		if errors.Is(err, types.ErrRevoked) {
			return err
		} else {
			// TODO: what log level
			bs, _ := json.Marshal(credentialToVerify)
			log.Logger().WithError(err).WithField("credential", string(bs)).Info("CredentialStatus verification failed")
		}
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

	// Check issuance/expiration time of the credential
	// if the signing key is valid at the given time is checked during signature verification
	validAtNotNil := time.Now()
	if validAt != nil {
		validAtNotNil = *validAt
	}
	if !credentialToVerify.ValidAt(validAtNotNil, maxSkew) {
		return types.ErrCredentialNotValidAtTime
	}

	// Check signature
	if checkSignature {
		issuerDID, _ := did.ParseDID(credentialToVerify.Issuer.String())
		_, _, err := v.didResolver.Resolve(*issuerDID, &resolver.ResolveMetadata{ResolveTime: validAt, AllowDeactivated: false})
		if err != nil {
			return fmt.Errorf("could not validate issuer: %w", err)
		}
		return v.VerifySignature(credentialToVerify, validAt)
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
		return errVerificationMethodNotOfIssuer
	}

	pk, err := v.keyResolver.ResolveKeyByID(revocation.Proof.VerificationMethod.String(), &revocation.Date, resolver.NutsSigningKeyType)
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

func (v verifier) VerifyVP(vp vc.VerifiablePresentation, verifyVCs bool, allowUntrustedVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error) {
	return v.doVerifyVP(&v, vp, verifyVCs, allowUntrustedVCs, validAt)
}

// doVerifyVP delegates VC verification to the supplied Verifier, to aid unit testing.
func (v verifier) doVerifyVP(vcVerifier Verifier, presentation vc.VerifiablePresentation, verifyVCs bool, allowUntrustedVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error) {
	// custom requirement: credentials may only be presented by subject
	if subjectDID, err := credential.PresenterIsCredentialSubject(presentation); err != nil {
		return nil, newVerificationError("presenter is credential subject: %w", err)
	} else if subjectDID == nil && len(presentation.VerifiableCredential) > 0 {
		return nil, newVerificationError("credential(s) must be presented by subject")
	}

	// check signature
	err := v.signatureVerifier.VerifyVPSignature(presentation, validAt)
	if err != nil {
		return nil, err
	}

	if verifyVCs {
		for _, current := range presentation.VerifiableCredential {
			err = vcVerifier.Verify(current, allowUntrustedVCs, true, validAt)
			if err != nil {
				return nil, newVerificationError("invalid VC (id=%s): %w", current.ID, err)
			}
		}
	}

	return presentation.VerifiableCredential, nil
}
