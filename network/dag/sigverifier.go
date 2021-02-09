package dag

import (
	crypto2 "crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// DocumentSignatureVerifier defines functions to verify document signatures.
type DocumentSignatureVerifier interface {
	Verify(input Document) error
}

// NewDocumentSignatureVerifier creates a DocumentSignatureVerifier that uses the given KeyResolver to resolves
// keys that aren't embedded in the document.
func NewDocumentSignatureVerifier(resolver crypto.KeyResolver) DocumentSignatureVerifier {
	return &documentVerifier{resolver: resolver}
}

type documentVerifier struct {
	resolver crypto.KeyResolver
}

func (d documentVerifier) Verify(input Document) error {
	var signingKey crypto2.PublicKey
	if input.SigningKey() != nil {
		if err := input.SigningKey().Raw(&signingKey); err != nil {
			return err
		}
	} else {
		pk, err := d.resolver.GetPublicKey(input.SigningKeyID(), input.SigningTime())
		if err != nil {
			return fmt.Errorf("unable to verify document signature, can't resolve key (kid=%s): %w", input.SigningKeyID(), err)
		}
		signingKey = pk
	}
	// TODO: jws.Verify parses the JWS again, which we already did when parsing the document. If we want to optimize
	// this we need to implement a custom verifier.
	_, err := jws.Verify(input.Data(), jwa.SignatureAlgorithm(input.SigningAlgorithm()), signingKey)
	return err
}
