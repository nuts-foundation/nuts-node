package network

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

type powerOnSelfTest interface {
	perform() error
}

func newPowerOnSelfTest(graph dag.DAG, publisher dag.Publisher, verifier dag.TransactionSignatureVerifier) powerOnSelfTest {
	post := &defaultPowerOnSelfTest{verifier: verifier, graph: graph}
	publisher.Subscribe(dag.AnyPayloadType, post.verifyTransactionSignature)
	return post
}

type defaultPowerOnSelfTest struct {
	verifier dag.TransactionSignatureVerifier
	graph    dag.DAG
	finished bool
	failure  error
}

func (post *defaultPowerOnSelfTest) perform() error {
	if !post.finished {
		if post.failure == nil {
			post.failure = post.verifyTransactions()
		}
		post.finished = true
	}
	if post.failure != nil {
		return fmt.Errorf("Power-On-Self-Test failed: %w", post.failure)
	}
	return nil
}

func (post *defaultPowerOnSelfTest) verifyTransactionSignature(tx dag.Transaction, _ []byte) error {
	if post.failure != nil || post.finished {
		// If we already encountered a failure or POST is already finished,
		// we don't need to waste CPU cycles checking transaction signatures.
		return nil
	}
	if err := post.verifier.Verify(tx); err != nil {
		post.failure = err
	}
	return nil
}

func (post *defaultPowerOnSelfTest) verifyTransactions() error {
	transactions, err := post.graph.FindBetween(dag.MinTime(), dag.MaxTime())
	if err != nil {
		return err
	}
	for _, tx := range transactions {
		for _, prev := range tx.Previous() {
			present, err := post.graph.IsPresent(prev)
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
