package p2p

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func Test_connection_close(t *testing.T) {
	t.Run("already closed", func(t *testing.T) {
		conn := newConnection(Peer{}, nil)
		conn.close()
		conn.close()
	})
}

func Test_connection_exchange(t *testing.T) {
	t.Run("EOF from Recv() stops call", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		messenger := NewMockgrpcMessenger(ctrl)

		messenger.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
			return nil, io.EOF
		})
		conn := newConnection(Peer{}, messenger)
		if !invokeWaitFor(func() {
			conn.exchange(messageQueue{})
		}, time.Second) {
			t.Fatal("expected exchange() to return due to Recv() EOF")
		}
	})
	t.Run("close() stops call", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		wg := sync.WaitGroup{}
		messenger := NewMockgrpcMessenger(ctrl)
		messenger.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
			wg.Wait()
			return nil, io.EOF
		})
		conn := newConnection(Peer{}, messenger)

		wg.Add(1)
		go func() {
			conn.exchange(messageQueue{})
			wg.Done()
		}()
		runtime.Gosched() // make sure exchange() goroutine is getting a slice of CPU

		conn.close()
		if !waitFor(&wg, time.Second) {
			t.Fatal("expected exchange() to return due to close()")
		}
	})
}

func Test_connection_send(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		messenger := NewMockgrpcMessenger(ctrl)

		// Signal waitgroup when a message is sent
		wg := sync.WaitGroup{}
		wg.Add(1)
		messenger.EXPECT().Send(gomock.Any()).DoAndReturn(func(_ interface{}) error {
			wg.Done()
			return nil
		})
		messenger.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
			wg.Wait()
			return nil, io.EOF
		})

		// Create connection, start message sending goroutine
		conn := newConnection(Peer{}, messenger)
		defer conn.close()
		go conn.exchange(messageQueue{})
		runtime.Gosched() // make sure exchange() goroutine is getting a slice of CPU

		// Send message and wait for it to be sent
		err := conn.send(&transport.NetworkMessage{})
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, waitFor(&wg, time.Second), "time-out while waiting for message to arrive")
	})
	t.Run("send on closed connection", func(t *testing.T) {
		conn := newConnection(Peer{}, nil)
		conn.close()
		err := conn.send(&transport.NetworkMessage{})
		assert.EqualError(t, err, "can't send on closed connection")
	})
}

func Test_connection_receiveMessages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const numMsg = 2
	numInvocations := int32(0)

	messenger := NewMockgrpcMessenger(ctrl)
	messenger.EXPECT().Recv().Times(numMsg + 1).DoAndReturn(func() (interface{}, error) {
		if atomic.AddInt32(&numInvocations, 1) <= numMsg {
			return &transport.NetworkMessage{}, nil
		} else {
			return nil, errors.New("connection closed")
		}
	})

	// Create connection, start message receiving goroutine
	conn := newConnection(Peer{}, messenger)
	defer conn.close()
	c := conn.receiveMessages()

	// Wait for numMsg to arrive
	wg := sync.WaitGroup{}
	wg.Add(numMsg)
	go func() {
		for {
			value := <-c
			if value != nil {
				wg.Done()
			} else {
				return
			}
		}
	}()
	if !waitFor(&wg, time.Second) {
		t.Fail()
	}
}

// Taken from https://stackoverflow.com/questions/32840687/timeout-for-waitgroup-wait
func waitFor(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true // completed normally
	case <-time.After(timeout):
		return false // timed out
	}
}

func invokeWaitFor(fn func(), timeout time.Duration) bool {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		fn()
		wg.Done()
	}()
	return waitFor(&wg, timeout)
}
