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

		recvWaiter := sync.WaitGroup{}
		recvWaiter.Add(1)
		messenger.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
			recvWaiter.Done()
			wg.Wait()
			return nil, io.EOF
		})
		conn := newConnection(Peer{}, messenger)

		wg.Add(1)
		go func() {
			conn.exchange(messageQueue{})
			wg.Done()
		}()
		// make sure exchange() called Recv(), otherwise the test will sometimes fail
		recvWaiter.Wait()

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
	c := receiveMessages(conn.ID, conn.messenger)

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

const addr = "bar"
const id = "foo"

func Test_connectionManager_register(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		mgr := newConnectionManager()
		conn := mgr.register(Peer{ID: id, Address: addr}, nil)
		assert.NotNil(t, conn)
		assert.Len(t, mgr.peersByAddr, 1)
	})
	t.Run("duplicate connection closes first", func(t *testing.T) {
		mgr := newConnectionManager()
		conn1 := mgr.register(Peer{ID: id, Address: addr}, nil).(*managedConnection)
		assert.Empty(t, conn1.closer) // assert first one connected
		// Now register second one, disconnect first
		conn2 := mgr.register(Peer{ID: id, Address: addr + "2"}, nil).(*managedConnection)
		assert.NotEmpty(t, conn1.closer) // assert first one disconnected
		assert.Empty(t, conn2.closer)    // assert second one connected

		assert.Len(t, mgr.peersByAddr, 1)
	})
}

func Test_connectionManager_get(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		mgr := newConnectionManager()
		conn := mgr.register(Peer{ID: id, Address: addr}, nil)
		assert.Equal(t, conn, mgr.get(id))
	})
	t.Run("does not exists", func(t *testing.T) {
		mgr := newConnectionManager()
		assert.Nil(t, mgr.get(id))
	})
}

func Test_connectionManager_isConnected(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		mgr := newConnectionManager()
		_ = mgr.register(Peer{ID: id, Address: addr}, nil)
		assert.True(t, mgr.isConnected(addr))
	})
	t.Run("does not exists", func(t *testing.T) {
		mgr := newConnectionManager()
		assert.False(t, mgr.isConnected(id))
	})
}

func Test_connectionManager_close(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		mgr := newConnectionManager()
		_ = mgr.register(Peer{ID: id, Address: addr}, nil)
		assert.True(t, mgr.close(id))
	})
	t.Run("does not exists", func(t *testing.T) {
		mgr := newConnectionManager()
		assert.False(t, mgr.close(id))
	})
}

func Test_connectionManager_stop(t *testing.T) {
	mgr := newConnectionManager()
	_ = mgr.register(Peer{ID: id, Address: addr}, nil)
	mgr.stop()
	assert.Empty(t, mgr.conns)
}

func Test_connectionManager_forEach(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		calls := 0
		mgr := newConnectionManager()
		mgr.forEach(func(conn connection) {
			calls++
		})
		assert.Equal(t, 0, calls)
	})
	t.Run("non-empty", func(t *testing.T) {
		calls := 0
		mgr := newConnectionManager()
		_ = mgr.register(Peer{ID: id, Address: addr}, nil)
		_ = mgr.register(Peer{ID: id + "2", Address: addr + "2"}, nil)
		mgr.forEach(func(conn connection) {
			calls++
		})
		assert.Equal(t, 2, calls)
	})
}
