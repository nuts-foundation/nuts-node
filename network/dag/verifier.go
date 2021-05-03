package dag

import (
	"fmt"
)

// Verifier defines the API of a DAG verifier, used to check the integrity of a DAG that's been loaded from disk.
type Verifier interface {
	// Verify checks the integrity of the DAG, returning an error when it failed.
	Verify() error
}

// NewVerifier creates a new DAG verifier.
func NewVerifier(graph DAG, publisher Publisher, verifier TransactionSignatureVerifier) Verifier {
	instance := &defaultVerifier{verifier: verifier, graph: graph}
	publisher.Subscribe(AnyPayloadType, instance.verifyTransactionSignature)
	return instance
}

type defaultVerifier struct {
	verifier TransactionSignatureVerifier
	graph    DAG
	finished bool
	failure  error
}

func (v *defaultVerifier) Verify() error {
	if !v.finished {
		if v.failure == nil {
			v.failure = v.verifyTransactions()
		}
		v.finished = true
	}
	if v.failure != nil {
		return fmt.Errorf("DAG verification failed: %w", v.failure)
	}
	return nil
}

func (v *defaultVerifier) verifyTransactionSignature(tx Transaction, _ []byte) error {
	if v.failure != nil || v.finished {
		// If we already encountered a failure or POST is already finished,
		// we don't need to waste CPU cycles checking transaction signatures.
		return nil
	}
	if err := v.verifier.Verify(tx); err != nil {
		v.failure = err
	}
	return nil
}

func (v *defaultVerifier) verifyTransactions() error {
	transactions, err := v.graph.FindBetween(MinTime(), MaxTime())
	if err != nil {
		return err
	}
	for _, tx := range transactions {
		for _, prev := range tx.Previous() {
			present, err := v.graph.IsPresent(prev)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("transaction is referring to non-existing previous transaction (tx=%s,prev=%s)", tx.Ref(), prev)
			}
		}
	}
	return nil
}
