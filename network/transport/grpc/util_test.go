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

package grpc

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func Test_ReceiveMessages(t *testing.T) {
	t.Run("receive message", func(t *testing.T) {
		received := 0

		streamer := StubStreamReceiver{}
		streamer.ExpectedMessage = &TestMessage{Data: []byte("foobar")}
		err := ReceiveMessages(&streamer, func() interface{} {
			return &TestMessage{}
		}, func(msg interface{}) {
			received++
			assert.Equal(t, string((msg.(*TestMessage)).Data), "foobar")
		})
		assert.Equal(t, err, &closedErr{})
		assert.Equal(t, received, 1)
	})
	t.Run("error", func(t *testing.T) {
		received := 0

		streamer := StubStreamReceiver{}
		expectedError := errors.New("some failure")
		streamer.ExpectedError = expectedError
		err := ReceiveMessages(&streamer, func() interface{} {
			var receivedMessage string
			return &receivedMessage
		}, func(msg interface{}) {
			received++
		})
		assert.Equal(t, err, expectedError)
		assert.Equal(t, received, 0)
	})
}

func Test_SendMessages(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sender := NewMockStreamSender(ctrl)
		expected := "message"
		wg := sync.WaitGroup{}
		wg.Add(1)
		sender.EXPECT().SendMsg(expected).Do(func(_ interface{}) {
			wg.Done()
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		send := SendMessages(ctx, transport.Peer{}, sender)
		err := send(expected)
		if !assert.NoError(t, err) {
			return
		}
		wg.Wait() // wait for SendMsg()
	})
	t.Run("unable to send", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sender := NewMockStreamSender(ctrl)
		expected := "message"
		wg := sync.WaitGroup{}
		wg.Add(1)
		sender.EXPECT().SendMsg(expected).DoAndReturn(func(_ interface{}) error {
			wg.Done()
			return errors.New("failed")
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		send := SendMessages(ctx, transport.Peer{}, sender)
		err := send(expected)
		if !assert.NoError(t, err) {
			return
		}
		wg.Wait() // wait for SendMsg()
	})

	t.Run("backlog full", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sender := NewMockStreamSender(ctrl)
		expected := "message"

		wg := &sync.WaitGroup{}
		wg.Add(1)

		sender.EXPECT().SendMsg(expected).AnyTimes().DoAndReturn(func(_ interface{}) error {
			// Block SendMsg() call, to simulate a (very) slow network or peer, so that the backlog fills.
			wg.Wait()
			return nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Fill backlog (some extra to account for test being to fast/random scheduling)
		send := SendMessages(ctx, transport.Peer{}, sender)
		for i := 0; i < 30; i++ {
			_ = send(expected)
		}

		// Send one more, which must trigger an error
		err := send(expected)
		t.Logf("last %v", err)
		assert.EqualError(t, err, "peer's outbound message backlog has reached max capacity, message is dropped (peer=@,backlog-size=20)")

		wg.Done() // signal SendMsg() to proceed, finishing the test
	})
}

func Test_readMetadata(t *testing.T) {
	t.Run("ok - roundtrip", func(t *testing.T) {
		peerID, nodeDID, err := readMetadata(metadata.New(map[string]string{
			peerIDHeader:  "1234",
			nodeDIDHeader: "did:nuts:test",
		}))
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "1234", peerID.String())
		assert.Equal(t, "did:nuts:test", nodeDID.String())
	})
	t.Run("error - multiple values for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		md.Append(peerIDHeader, "1")
		md.Append(peerIDHeader, "2")
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent multiple values for peerID header")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
	t.Run("error - no values for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer didn't send peerID header")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
	t.Run("error - empty value for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		md.Set(peerIDHeader, "  ")
		peerID, _, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent empty peerID header")
		assert.Empty(t, peerID.String())
	})
	t.Run("error - invalid node DID", func(t *testing.T) {
		md := metadata.MD{}
		md.Set(peerIDHeader, "1")
		md.Set(nodeDIDHeader, "invalid")
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent invalid node DID: invalid DID: input does not begin with 'did:' prefix")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
}
