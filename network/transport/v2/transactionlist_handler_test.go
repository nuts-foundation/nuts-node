/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestTransactionListHandler(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	t.Run("fn is called", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		value := atomic.Value{}
		handlerFunc := func(_ context.Context, connection grpc.Connection, envelope *Envelope) error {
			value.Store(true)
			return nil
		}
		tlh := newTransactionListHandler(ctx, handlerFunc)
		go tlh.start()

		tlh.ch <- connectionEnvelope{}

		test.WaitFor(t, func() (bool, error) {
			return value.Load() == true, nil
		}, time.Second, "timeout while waiting for message handling")
	})
}
func TestProtocol_handleTransactionList(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)
	h1 := tx.Ref()
	data := tx.Data()
	payload := []byte{2}
	request := &Envelope_TransactionListQuery{TransactionListQuery: &TransactionListQuery{Refs: [][]byte{h1.Slice()}}}
	envelopeWithConversation := func(conversation *conversation) *Envelope {
		return &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
				TotalMessages:  1,
				MessageNumber:  1,
			},
		}}
	}
	peer := transport.Peer{ID: "peerID"}

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(context.Background(), connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("supports cancellations", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := p.handleTransactionList(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - duplicate", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(context.Background(), connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - missing prevs", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(dag.ErrPreviousTransactionMissing)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(hash.FromSlice([]byte("stateXor")), uint32(7))
		mocks.Sender.EXPECT().sendState(connection, hash.FromSlice([]byte("stateXor")), uint32(7))

		err := p.handleTransactionList(context.Background(), connection, envelope)

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("ok - conversation marked as done", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(context.Background(), connection, envelope)

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("ok - conversation not marked as done", func(t *testing.T) {
		tx2, _, _ := dag.CreateTestTransaction(0)
		request2 := &Envelope_TransactionListQuery{TransactionListQuery: &TransactionListQuery{Refs: [][]byte{h1.Slice(), tx2.Ref().Slice()}}}
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request2, peer)
		cStartTime := conversation.expiry.Add(-1 * time.Millisecond)
		conversation.expiry = cStartTime
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(context.Background(), connection, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
				TotalMessages:  2,
				MessageNumber:  1,
			},
		}})

		assert.NoError(t, err)
		assert.NotNil(t, p.cMan.conversations[conversation.conversationID.String()])
		// timeout is reset
		assert.True(t, conversation.expiry.After(cStartTime))
	})

	t.Run("error - State.Add failed", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		envelope := envelopeWithConversation(conversation)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(errors.New("custom"))

		err := p.handleTransactionList(context.Background(), connection, envelope)

		assert.EqualError(t, err, fmt.Sprintf("unable to add received transaction to DAG (tx=%s): custom", tx.Ref().String()))
	})

	t.Run("error - missing payload for TX without PAL", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)

		err := p.handleTransactionList(context.Background(), connection, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data}},
			},
		}})

		assert.ErrorContains(t, err, "peer did not provide payload for transaction")
	})

	t.Run("error - invalid transaction", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)

		err := p.handleTransactionList(context.Background(), connection, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: []byte{1}}},
			},
		}})

		assert.EqualError(t, err, "received transaction is invalid: unable to parse transaction: invalid compact serialization format: invalid number of segments")
	})

	t.Run("error - unknown conversationID", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversationID := newConversationID()

		err := p.handleTransactionList(context.Background(), connection, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
			},
		}})

		assert.EqualError(t, err, fmt.Sprintf("unknown or expired conversation (id=%s)", conversationID.String()))
	})
}
