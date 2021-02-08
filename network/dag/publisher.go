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
	dag.RegisterObserver(publisher.DocumentAdded)
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

func (s *replayingDAGPublisher) DocumentAdded(document interface{}) {
	doc := document.(Document)
	// Received new document, add it to the subscription walker resume list so it resumes from this document
	// when the payload is received.
	s.algo.resumeAt.PushBack(doc.Ref())
	s.publish(doc.Ref())
}

func (s *replayingDAGPublisher) Subscribe(documentType string, receiver Receiver) {
	oldSubscriber := s.subscribers[documentType]
	s.subscribers[documentType] = func(document SubscriberDocument, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(document, payload); err != nil {
				return err
			}
		}
		return receiver(document, payload)
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
	err := s.dag.Walk(s.algo, s.publishDocument, startAt)
	if err != nil {
		log.Logger().Errorf("Unable to publish DAG: %v", err)
	}
}

func (s *replayingDAGPublisher) publishDocument(document Document) bool {
	receiver := s.subscribers[document.PayloadType()]
	if receiver == nil {
		return true
	}
	payload, err := s.payloadStore.ReadPayload(document.PayloadHash())
	if err != nil {
		log.Logger().Errorf("Unable to read payload to publish DAG: (ref=%s) %v", document.Ref(), err)
		return false
	}
	if payload == nil {
		// We haven't got the payload, break of processing for this branch
		return false
	}
	if err := receiver(document, payload); err != nil {
		log.Logger().Errorf("Document subscriber returned an error (ref=%s,type=%s): %v", document.Ref(), document.PayloadType(), err)
	}
	return true
}
