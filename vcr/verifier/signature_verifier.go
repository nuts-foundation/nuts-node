package verifier

import (
	crypt "crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

type signatureVerifier struct {
	keyResolver   resolver.KeyResolver
	jsonldManager jsonld.JSONLD
}

// VerifySignature checks if the signature on a VP is valid at a given time
func (sv *signatureVerifier) VerifySignature(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
	switch credentialToVerify.Format() {
	case issuer.JSONLDCredentialFormat:
		return sv.jsonldProof(credentialToVerify, credentialToVerify.Issuer.String(), validateAt)
	case issuer.JWTCredentialFormat:
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
	case issuer.JSONLDPresentationFormat:
		return sv.jsonldProof(presentation, signerDID.String(), validateAt)
	case issuer.JWTPresentationFormat:
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
	signingKey, err := sv.keyResolver.ResolveKeyByID(ldProof.VerificationMethod.String(), at, resolver.NutsSigningKeyType)
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
		return sv.resolveSigningKey(kid, issuer, at)
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

func (sv *signatureVerifier) resolveSigningKey(kid string, issuer string, at *time.Time) (crypt.PublicKey, error) {
	// Compatibility: VC data model v1 puts key discovery out of scope and does not require the `kid` header.
	// When `kid` isn't present use the JWT issuer as `kid`, then it is at least compatible with DID methods that contain a single verification method (did:jwk).
	if kid == "" {
		kid = issuer
	}
	if strings.HasPrefix(kid, "did:jwk:") && !strings.Contains(kid, "#") {
		kid += "#0"
	}
	return sv.keyResolver.ResolveKeyByID(kid, at, resolver.NutsSigningKeyType)
}
