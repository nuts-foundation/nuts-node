package dag

import (
	crypto2 "crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// TransactionSignatureVerifier defines functions to verify transaction signatures.
type TransactionSignatureVerifier interface {
	Verify(input Transaction) error
}

// NewTransactionSignatureVerifier creates a TransactionSignatureVerifier that uses the given KeyResolver to resolves
// keys that aren't embedded in the transaction.
func NewTransactionSignatureVerifier(resolver types.KeyResolver) TransactionSignatureVerifier {
	return &transactionVerifier{resolver: resolver}
}

type transactionVerifier struct {
	resolver types.KeyResolver
}

func (d transactionVerifier) Verify(input Transaction) error {
	var signingKey crypto2.PublicKey
	if input.SigningKey() != nil {
		if err := input.SigningKey().Raw(&signingKey); err != nil {
			return err
		}
	} else {
		pk, err := d.resolver.ResolvePublicKey(input.SigningKeyID(), input.SigningTime())
		if err != nil {
			return fmt.Errorf("unable to verify transaction signature, can't resolve key (kid=%s): %w", input.SigningKeyID(), err)
		}
		signingKey = pk
	}
	// TODO: jws.Verify parses the JWS again, which we already did when parsing the transaction. If we want to optimize
	// this we need to implement a custom verifier.
	_, err := jws.Verify(input.Data(), jwa.SignatureAlgorithm(input.SigningAlgorithm()), signingKey)
	return err
}
