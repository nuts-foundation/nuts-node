package dag

import (
	crypto2 "crypto"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

// ErrPreviousTransactionMissing indicates one or more of the previous transactions (which the transaction refers to)
// is missing.
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

// NewSigningTimeVerifier creates a transaction verifier that asserts that signing time of transactions aren't
// further than 1 day in the future, since that complicates head calculation.
func NewSigningTimeVerifier() Verifier {
	return func(tx Transaction, _ DAG) error {
		if time.Now().Add(24 * time.Hour).Before(tx.SigningTime()) {
			return fmt.Errorf("transaction signing time too far in the future: %s", tx.SigningTime())
		}
		return nil
	}
}

// NewBootTimeVerifier creates a BootTimeVerifier. See BootTimeVerifier for its usage.
func NewBootTimeVerifier(publisher Publisher, graph DAG, verifiers ...Verifier) BootTimeVerifier {
	btf := &subscribingBootTimeVerifier{graph: graph, verifiers: verifiers}
	sub := NewOnOffSubscriber(publisher, btf.verify)
	btf.sub = sub
	return btf
}

// subscribingBootTimeVerifier is a verifier that can be used after loading a DAG from disk to verify its transactions.
// It does not exactly replicate the context of the DAG when a transaction was added, so it should only execute verifiers check deterministic variables (e.g. signatures).
// It is called by letting the given publisher publish the transactions on the loaded DAG. When the publisher has finished publishing all transactions from the loaded DAG,
// BootFinished must be called to retrieve any verification failures that might have occurred. If no errors are returned, all transactions successfully were verified.
type subscribingBootTimeVerifier struct {
	verifiers            []Verifier
	graph                DAG
	verificationFailures []error
	sub                  *OnOffSubscriber
}

func (btf *subscribingBootTimeVerifier) verify(tx Transaction, payload []byte) error {
	for _, verifier := range btf.verifiers {
		err := verifier(tx, btf.graph)
		if err != nil {
			btf.verificationFailures = append(btf.verificationFailures, err)
		}
	}
	return nil
}

// BootFinished signals the verifier that boot has finished and that it should stop verifying transactions.
// It returns all verification failures that have been collected.
func (btf *subscribingBootTimeVerifier) BootFinished() []error {
	btf.sub.On = false
	return btf.verificationFailures
}
