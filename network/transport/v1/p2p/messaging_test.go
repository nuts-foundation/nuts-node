/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package p2p

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func Test_exchange(t *testing.T) {
	t.Run("EOF from Recv() stops call", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		messenger := NewMockgrpcMessenger(ctrl)

		messenger.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
			return nil, io.EOF
		})
		if !invokeWaitFor(func() {
			exchange(transport.Peer{}, messageQueue{}, make(chan *protobuf.NetworkMessage, 1), messenger, make(chan struct{}, 1), func() {})
		}, time.Second) {
			t.Fatal("expected exchange() to return due to Recv() EOF")
		}
	})
	t.Run("closer stops call", func(t *testing.T) {
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

		closer := make(chan struct{}, 1)

		wg.Add(1)
		go func() {
			exchange(transport.Peer{}, messageQueue{}, make(chan *protobuf.NetworkMessage, 1), messenger, closer, func() {})
			wg.Done()
		}()
		// make sure exchange() called Recv(), otherwise the test will sometimes fail
		recvWaiter.Wait()

		closer <- struct{}{}
		if !waitFor(&wg, time.Second) {
			t.Fatal("expected exchange() to return due to closer")
		}
	})
	t.Run("backlog is full", func(t *testing.T) {
		const backlogSize = 5

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		messenger := NewMockgrpcMessenger(ctrl)

		var callCount int32
		messenger.EXPECT().Recv().Times(backlogSize + 2).DoAndReturn(func() (interface{}, error) {
			if atomic.AddInt32(&callCount, 1) >= backlogSize+2 {
				return nil, io.EOF
			}
			return &protobuf.NetworkMessage{}, nil
		})

		q := messageQueue{c: make(chan PeerMessage, backlogSize)}

		// When the inbound queue is full it shouldn't block, and since Recv() returns EOF after backlog + 1,
		// exchange() shouldn't block.
		exchange(transport.Peer{}, q, make(chan *protobuf.NetworkMessage, 1), messenger, make(chan struct{}, 1), func() {})

		assert.Len(t, q.c, backlogSize)
	})
}

func Test_receiveMessages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const numMsg = 2
	numInvocations := int32(0)

	messenger := NewMockgrpcMessenger(ctrl)
	messenger.EXPECT().Recv().Times(numMsg + 1).DoAndReturn(func() (interface{}, error) {
		if atomic.AddInt32(&numInvocations, 1) <= numMsg {
			return &protobuf.NetworkMessage{}, nil
		} else {
			return nil, errors.New("connection closed")
		}
	})

	// Create connection, start message receiving goroutine
	c := receiveMessages("foo", messenger)

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
