package dag

import (
	crypto2 "crypto"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrPreviousTransactionMissing indicates one or more of the previous transcations (which the transaction refers to)
// is misisng.
var ErrPreviousTransactionMissing = errors.New("transaction is referring to non-existing previous transaction")

// Verifier defines the API of a DAG verifier, used to check the validity of a transaction.
type Verifier func(tx Transaction, graph DAG) error

// NewTransactionSignatureVerifier creates a transaction verifier that checks the signature of the transaction.
// It uses the given KeyResolver to resolves keys that aren't embedded in the transaction.
func NewTransactionSignatureVerifier(resolver types.KeyResolver) Verifier {
	return func(tx Transaction, _ DAG) error {
		var signingKey crypto2.PublicKey
		if tx.SigningKey() != nil {
			if err := tx.SigningKey().Raw(&signingKey); err != nil {
				return err
			}
		} else {
			signingTime := tx.SigningTime()
			pk, err := resolver.ResolvePublicKey(tx.SigningKeyID(), &signingTime)
			if err != nil {
				return fmt.Errorf("unable to verify transaction signature, can't resolve key (kid=%s): %w", tx.SigningKeyID(), err)
			}
			signingKey = pk
		}
		// TODO: jws.Verify parses the JWS again, which we already did when parsing the transaction. If we want to optimize
		// this we need to implement a custom verifier.
		_, err := jws.Verify(tx.Data(), jwa.SignatureAlgorithm(tx.SigningAlgorithm()), signingKey)
		return err
	}
}

// NewPrevTransactionsVerifier creates a transaction verifier that asserts that all previous transactions are known.
func NewPrevTransactionsVerifier() Verifier {
	return func(tx Transaction, graph DAG) error {
		for _, prev := range tx.Previous() {
			present, err := graph.IsPresent(prev)
			if err != nil {
				return err
			}
			if !present {
				return ErrPreviousTransactionMissing
			}
		}
		return nil
	}
}
