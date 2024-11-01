/*
 * Copyright (C) 2024 Nuts community
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
	crypt "crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vdr/didx509"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

type signatureVerifier struct {
	keyResolver   resolver.KeyResolver
	jsonldManager jsonld.JSONLD
}

var ExtractProtectedHeaders = didx509.ExtractProtectedHeaders

// VerifySignature checks if the signature on a VP is valid at a given time
func (sv *signatureVerifier) VerifySignature(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
	switch credentialToVerify.Format() {
	case vc.JSONLDCredentialProofFormat:
		return sv.jsonldProof(credentialToVerify, credentialToVerify.Issuer.String(), validateAt)
	case vc.JWTCredentialProofFormat:
		return sv.jwtSignature(credentialToVerify.Raw(), credentialToVerify.Issuer.String(), validateAt)
	default:
		return errors.New("unsupported credential proof format")
	}
}

// VerifyVPSignature checks if the signature on a VP is valid at a given time
func (sv *signatureVerifier) VerifyVPSignature(presentation vc.VerifiablePresentation, validateAt *time.Time) error {
	signerDID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return toVerificationError(err)
	}

	switch presentation.Format() {
	case vc.JSONLDPresentationProofFormat:
		return sv.jsonldProof(presentation, signerDID.String(), validateAt)
	case vc.JWTPresentationProofFormat:
		return sv.jwtSignature(presentation.Raw(), signerDID.String(), validateAt)
	default:
		return errors.New("unsupported presentation proof format")
	}
}

// jsonldProof implements the Proof Verification Algorithm: https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
func (sv *signatureVerifier) jsonldProof(documentToVerify any, issuer string, at *time.Time) error {
	signedDocument, err := proof.NewSignedDocument(documentToVerify)
	if err != nil {
		return newVerificationError("invalid LD-JSON document: %w", err)
	}

	ldProof := proof.LDProof{}
	if err = signedDocument.UnmarshalProofValue(&ldProof); err != nil {
		return newVerificationError("unsupported proof type: %w", err)
	}

	// for a VP this will not fail
	verificationMethod := ldProof.VerificationMethod.String()
	if verificationMethod == "" {
		return newVerificationError("missing proof")
	}
	verificationMethodIssuer := strings.Split(verificationMethod, "#")[0]
	if verificationMethodIssuer == "" || verificationMethodIssuer != issuer {
		return errVerificationMethodNotOfIssuer
	}

	// verify signing time
	validAt := time.Now()
	if at != nil {
		validAt = *at
	}
	if !ldProof.ValidAt(validAt, maxSkew) {
		return toVerificationError(types.ErrPresentationNotValidAtTime)
	}

	// find key
	metadata := &resolver.ResolveMetadata{
		ResolveTime: at,
	}
	signingKey, err := sv.keyResolver.ResolveKeyByID(ldProof.VerificationMethod.String(), metadata, resolver.NutsSigningKeyType)
	if err != nil {
		return fmt.Errorf("unable to resolve valid signing key: %w", err)
	}

	// verify signature
	err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: sv.jsonldManager.DocumentLoader()}, signingKey)
	if err != nil {
		return newVerificationError("invalid signature: %w", err)
	}
	return nil
}

func (sv *signatureVerifier) jwtSignature(jwtDocumentToVerify string, issuer string, at *time.Time) error {
	var keyID string
	_, err := crypto.ParseJWT(jwtDocumentToVerify, func(kid string) (crypt.PublicKey, error) {
		keyID = kid
		metadata := &resolver.ResolveMetadata{
			ResolveTime: at,
		}
		headers, err := ExtractProtectedHeaders(jwtDocumentToVerify)
		if err != nil {
			return nil, err
		}
		metadata.JwtProtectedHeaders = headers
		return sv.resolveSigningKey(kid, issuer, metadata)
	}, jwt.WithClock(jwt.ClockFunc(func() time.Time {
		if at == nil {
			return time.Now()
		}
		return *at
	})))
	if err != nil {
		return fmt.Errorf("unable to validate JWT signature: %w", err)
	}
	if keyID != "" && strings.Split(keyID, "#")[0] != issuer {
		return errVerificationMethodNotOfIssuer
	}
	return nil
}

func (sv *signatureVerifier) resolveSigningKey(kid string, issuer string, metadata *resolver.ResolveMetadata) (crypt.PublicKey, error) {
	// Compatibility: VC data model v1 puts key discovery out of scope and does not require the `kid` header.
	// When `kid` isn't present use the JWT issuer as `kid`, then it is at least compatible with DID methods that contain a single verification method (did:jwk).
	if kid == "" {
		kid = issuer
	}
	if strings.HasPrefix(kid, "did:jwk:") && !strings.Contains(kid, "#") {
		kid += "#0"
	}
	return sv.keyResolver.ResolveKeyByID(kid, metadata, resolver.NutsSigningKeyType)
}
