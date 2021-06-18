package p2p
//
//import (
//	"errors"
//	"github.com/golang/mock/gomock"
//	"github.com/nuts-foundation/nuts-node/network/transport"
//	"github.com/stretchr/testify/assert"
//	"sync"
//	"testing"
//	"time"
//)
//
//func Test_connection_close(t *testing.T) {
//	t.Run("already closed", func(t *testing.T) {
//		conn := createConnection(Peer{}, nil)
//		conn.close()
//		conn.close()
//	})
//}
//
//func Test_connection_send(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		ctrl := gomock.NewController(t)
//		defer ctrl.Finish()
//		messenger := NewMockgrpcMessenger(ctrl)
//
//		// Signal waitgroup when a message is sent
//		wg := sync.WaitGroup{}
//		wg.Add(1)
//		messenger.EXPECT().Send(gomock.Any()).DoAndReturn(func(_ interface{}) error {
//			wg.Done()
//			return nil
//		})
//
//		// Create connection, start message sending goroutine
//		conn := createConnection(Peer{}, messenger)
//		defer conn.close()
//		go conn.sendMessages()
//
//		// Send message and wait for it to be sent
//		err := conn.send(&transport.NetworkMessage{})
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.True(t, waitFor(&wg, time.Second), "time-out while waiting for message to arrive")
//	})
//	t.Run("send on closed connection", func(t *testing.T) {
//		conn := createConnection(Peer{}, nil)
//		conn.close()
//		err := conn.send(&transport.NetworkMessage{})
//		assert.EqualError(t, err, "can't send on closed connection")
//	})
//}
//
//func Test_connection_receive(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	messenger := NewMockgrpcMessenger(ctrl)
//	messenger.EXPECT().Recv().Return(&transport.NetworkMessage{}, nil)
//	messenger.EXPECT().Recv().Return(&transport.NetworkMessage{}, nil)
//	messenger.EXPECT().Recv().Return(nil, errors.New("connection closed"))
//
//	// Create connection, start message receiving goroutine
//	conn := createConnection(Peer{}, messenger)
//	defer conn.close()
//	mq := messageQueue{c: make(chan PeerMessage, 10)}
//	conn.receiveMessages(mq)
//
//	// 2 messages received
//	assert.Len(t, mq.c, 2)
//}
//
//// Taken from https://stackoverflow.com/questions/32840687/timeout-for-waitgroup-wait
//func waitFor(wg *sync.WaitGroup, timeout time.Duration) bool {
//	c := make(chan struct{})
//	go func() {
//		defer close(c)
//		wg.Wait()
//	}()
//	select {
//	case <-c:
//		return true // completed normally
//	case <-time.After(timeout):
//		return false // timed out
//	}
//}
