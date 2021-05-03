package dag

import (
	crypto2 "crypto"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Verifier defines the API of a DAG verifier, used to check the validity of a transaction.
type Verifier interface {
	// Verify checks the integrity of the given transaction.
	Verify(tx Transaction, graph DAG) error
}

// NewTransactionSignatureVerifier creates a transaction verifier that checks the signature of the transaction.
// It uses the given KeyResolver to resolves keys that aren't embedded in the transaction.
func NewTransactionSignatureVerifier(resolver types.KeyResolver) Verifier {
	return &transactionVerifier{resolver: resolver}
}

type transactionVerifier struct {
	resolver types.KeyResolver
}

func (d transactionVerifier) Verify(input Transaction, _ DAG) error {
	var signingKey crypto2.PublicKey
	if input.SigningKey() != nil {
		if err := input.SigningKey().Raw(&signingKey); err != nil {
			return err
		}
	} else {
		signingTime := input.SigningTime()
		pk, err := d.resolver.ResolvePublicKey(input.SigningKeyID(), &signingTime)
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

// NewPrevTransactionsVerifier creates a transaction verifier that asserts that all previous transactions are known.
func NewPrevTransactionsVerifier() Verifier {
	return &prevTransactionsVerifier{}
}

type prevTransactionsVerifier struct {
}

func (v *prevTransactionsVerifier) Verify(tx Transaction, graph DAG) error {
	for _, prev := range tx.Previous() {
		present, err := graph.IsPresent(prev)
		if err != nil {
			return err
		}
		if !present {
			return errors.New("transaction is referring to non-existing previous transaction")
		}
	}
	return nil
}
