package dag

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// NewReplayingDAGPublisher creates a DAG publisher that replays the complete DAG to all subscribers when started.
func NewReplayingDAGPublisher(payloadStore PayloadStore, dag DAG) Publisher {
	publisher := &replayingDAGPublisher{
		subscribers:  map[string]Receiver{},
		algo:         NewBFSWalkerAlgorithm().(*bfsWalkerAlgorithm),
		payloadStore: payloadStore,
		dag:          dag,
	}
	dag.RegisterObserver(publisher.TransactionAdded)
	payloadStore.RegisterObserver(publisher.PayloadWritten)
	return publisher
}

type replayingDAGPublisher struct {
	subscribers  map[string]Receiver
	algo         *bfsWalkerAlgorithm
	payloadStore PayloadStore
	dag          DAG
}

func (s *replayingDAGPublisher) PayloadWritten(_ interface{}) {
	s.publish(hash.EmptyHash())
}

func (s *replayingDAGPublisher) TransactionAdded(transaction interface{}) {
	tx := transaction.(Transaction)
	// Received new transaction, add it to the subscription walker resume list so it resumes from this transaction
	// when the payload is received.
	s.algo.resumeAt.PushBack(tx.Ref())
	s.publish(tx.Ref())
}

func (s *replayingDAGPublisher) Subscribe(payloadType string, receiver Receiver) {
	oldSubscriber := s.subscribers[payloadType]
	s.subscribers[payloadType] = func(transaction Transaction, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(transaction, payload); err != nil {
				return err
			}
		}
		return receiver(transaction, payload)
	}
}

func (s replayingDAGPublisher) Start() {
	root, err := s.dag.Root()
	if err != nil {
		log.Logger().Errorf("Unable to retrieve DAG root for replaying subscriptions: %v", err)
		return
	}
	if !root.Empty() {
		s.publish(root)
	}
}

func (s *replayingDAGPublisher) publish(startAt hash.SHA256Hash) {
	err := s.dag.Walk(s.algo, s.publishTransaction, startAt)
	if err != nil {
		log.Logger().Errorf("Unable to publish DAG: %v", err)
	}
}

func (s *replayingDAGPublisher) publishTransaction(transaction Transaction) bool {
	payload, err := s.payloadStore.ReadPayload(transaction.PayloadHash())
	if err != nil {
		log.Logger().Errorf("Unable to read payload to publish DAG: (ref=%s) %v", transaction.Ref(), err)
		return false
	}
	if payload == nil {
		// We haven't got the payload, break of processing for this branch
		return false
	}

	for _, payloadType := range []string{transaction.PayloadType(), AnyPayloadType} {
		receiver := s.subscribers[payloadType]
		if receiver == nil {
			continue
		}
		if err := receiver(transaction, payload); err != nil {
			log.Logger().Errorf("Transaction subscriber returned an error (ref=%s,type=%s): %v", transaction.Ref(), transaction.PayloadType(), err)
		}
	}
	return true
}

// NewOnOffSubscriber creates a subscriber that can be switched off. It directly subscribes to any payload type and is default on.
func NewOnOffSubscriber(publisher Publisher, receiver Receiver) *OnOffSubscriber {
	sub := &OnOffSubscriber{receiver: receiver, On: true}
	publisher.Subscribe(AnyPayloadType, sub.receive)
	return sub
}

// OnOffSubscriber is a subscriber that can be switched off. It directly subscribes to any payload type and is default on.
type OnOffSubscriber struct {
	On       bool
	receiver Receiver
}

func (sub *OnOffSubscriber) receive(transaction Transaction, payload []byte) error {
	if sub.On {
		return sub.receiver(transaction, payload)
	}
	return nil
}
