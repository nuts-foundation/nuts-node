package p2p

import (
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"sync"
)

type stubMessenger struct {
	out []*protobuf.NetworkMessage
	sync.Mutex
	recvWaitGroup sync.WaitGroup
}

func (s *stubMessenger) MessagesSent() int {
	s.Lock()
	defer s.Unlock()
	return len(s.out)
}

func (s *stubMessenger) Send(message *protobuf.NetworkMessage) error {
	s.Lock()
	defer s.Unlock()
	s.out = append(s.out, message)
	return nil
}

func (s *stubMessenger) Recv() (*protobuf.NetworkMessage, error) {
	s.recvWaitGroup.Add(1)
	s.recvWaitGroup.Wait()
	return nil, nil
}
