/* Copyright (C) 2021 Nuts community
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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

func Test_adapter_Send(t *testing.T) {
	const peerID = "foobar"
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		// Mock messenger just to pass a valid object into acceptPeer() that wont error
		messenger := NewMockgrpcMessenger(ctrl)
		messenger.EXPECT().Send(gomock.Any()).AnyTimes()
		messenger.EXPECT().Recv().AnyTimes()

		adapter := NewAdapter().(*adapter)
		closer := make(chan struct{}, 1)
		ctx := adapter.acceptPeer(transport.Peer{ID: peerID}, messenger, closer)
		err := adapter.Send(peerID, &protobuf.NetworkMessage{})
		if !assert.NoError(t, err) {
			return
		}
		ctx.Done()
		closer <- struct{}{}

		adapter.peerMux.Lock()
		defer adapter.peerMux.Unlock()
		assert.Len(t, adapter.peerOutMessages[peerID], 1)
	})
	t.Run("unknown peer", func(t *testing.T) {
		adapter := NewAdapter().(*adapter)
		err := adapter.Send(peerID, &protobuf.NetworkMessage{})
		assert.EqualError(t, err, "unknown peer: foobar")
	})
	t.Run("concurrent call on closing connection", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		messenger := NewMockgrpcMessenger(ctrl)
		// sometimes these will get called, sometimes not (because the scheduling of the goroutines below is unknown, whether Send() or the closer will be called and handled first)
		messenger.EXPECT().Send(gomock.Any()).AnyTimes()
		messenger.EXPECT().Recv().AnyTimes()

		adapter := NewAdapter().(*adapter)
		closer := make(chan struct{}, 1)
		_ = adapter.acceptPeer(transport.Peer{ID: peerID}, messenger, closer)
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = adapter.Send(peerID, &protobuf.NetworkMessage{})
		}()
		go func() {
			defer wg.Done()
			closer <- struct{}{}
		}()
		wg.Wait()
	})
	t.Run("backlog is full", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		messenger := NewMockgrpcMessenger(ctrl)

		// Make sure Send() doesn't process messages from the backlog draining it, so block it until the test finishes.
		wg := sync.WaitGroup{}
		wg.Add(1)
		messenger.EXPECT().Send(gomock.Any()).MinTimes(1).DoAndReturn(func(_ interface{}) error {
			wg.Wait()
			return nil
		})
		messenger.EXPECT().Recv().AnyTimes().DoAndReturn(func() (interface{}, error) {
			// Recv() is also called, so let it wait as well.
			wg.Wait()
			return nil, nil
		})

		closer := make(chan struct{}, 1)
		defer func() {
			closer <- struct{}{}
		}()
		adapter := NewAdapter().(*adapter)
		_ = adapter.acceptPeer(transport.Peer{ID: peerID}, messenger, closer)

		for i := 0; i < outMessagesBacklog+1; i++ {
			err := adapter.Send(peerID, &protobuf.NetworkMessage{})
			if !assert.NoError(t, err) {
				return
			}
		}
		// This last one should spill the bucket
		err := adapter.Send(peerID, &protobuf.NetworkMessage{})
		assert.EqualError(t, err, "peer's outbound message backlog has reached max capacity, message is dropped (peer=foobar,backlog-size=1000)")
		assert.Len(t, adapter.peerOutMessages[peerID], outMessagesBacklog)

		wg.Done()
	})
}

func Test_adapter_Broadcast(t *testing.T) {
	const peer1ID = "foobar1"
	const peer2ID = "foobar2"
	adapter := NewAdapter().(*adapter)

	messenger1 := &stubMessenger{}
	messenger2 := &stubMessenger{}

	closer := make(chan struct{}, 1)

	_ = adapter.acceptPeer(transport.Peer{ID: peer1ID}, messenger1, closer)
	_ = adapter.acceptPeer(transport.Peer{ID: peer2ID}, messenger2, closer)

	adapter.Broadcast(&protobuf.NetworkMessage{})

	test.WaitFor(t, func() (bool, error) {
		return messenger1.MessagesSent() == 1, nil
	}, time.Second, "waiting for messages sent to node1")
	test.WaitFor(t, func() (bool, error) {
		return messenger2.MessagesSent() == 1, nil
	}, time.Second, "waiting for messages sent to node2")
}
