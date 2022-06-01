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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
)

func TestConversationID(t *testing.T) {
	t.Run("new creates a v4 uuid", func(t *testing.T) {
		cid := newConversationID()

		u, err := uuid.Parse(cid.String())

		assert.NoError(t, err)
		assert.Equal(t, uuid.Version(4), u.Version())
	})

	t.Run("String returns uuid as string", func(t *testing.T) {
		cid := newConversationID()

		s := cid.String()

		assert.Len(t, s, 36)
	})

	t.Run("slice() returns string as bytes", func(t *testing.T) {
		cid := newConversationID()

		bytes := cid.slice()

		assert.Equal(t, cid.String(), string(bytes))
	})
}

func TestNewConversationManager(t *testing.T) {
	cMan := newConversationManager(maxValidity)

	assert.Equal(t, maxValidity, cMan.validity)
	assert.NotNil(t, cMan.conversations)
}

func TestConversationManager_start(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	cMan := newConversationManager(time.Millisecond)
	cMan.start(ctx)
	envelope := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{},
	}

	_ = cMan.startConversation(envelope, "peerID")

	test.WaitFor(t, func() (bool, error) {
		cMan.mutex.Lock()
		defer cMan.mutex.Unlock()
		return len(cMan.conversations) == 0, nil
	}, time.Second, "timeout while waiting for conversations to clear")
}

func TestConversationManager_startConversation(t *testing.T) {
	msg := &Envelope_TransactionListQuery{TransactionListQuery: &TransactionListQuery{}}
	t.Run("peers first conversation", func(t *testing.T) {
		cMan := newConversationManager(time.Millisecond)

		conv := cMan.startConversation(msg, "peer")

		assert.NotNil(t, conv)
		assert.Len(t, cMan.conversations, 1)
		assert.Len(t, cMan.lastPeerConversationID, 1)
		assert.Equal(t, conv.conversationID, cMan.lastPeerConversationID["peer"])
	})
	t.Run("previous conversation still active", func(t *testing.T) {
		cMan := newConversationManager(time.Millisecond)
		previousConv := cMan.startConversation(msg, "peer")

		conv := cMan.startConversation(msg, "peer")

		assert.Nil(t, conv)
		assert.Len(t, cMan.conversations, 1)
		assert.Len(t, cMan.lastPeerConversationID, 1)
		assert.Equal(t, previousConv.conversationID, cMan.lastPeerConversationID["peer"])
	})
	t.Run("State is not blocking", func(t *testing.T) {
		msg := &Envelope_State{State: &State{}}
		cMan := newConversationManager(time.Millisecond)
		_ = cMan.startConversation(msg, "peer")

		conv := cMan.startConversation(msg, "peer")

		assert.NotNil(t, conv)
		assert.Len(t, cMan.conversations, 2)
		assert.Len(t, cMan.lastPeerConversationID, 0)
	})
	t.Run("previous conversation marked done", func(t *testing.T) {
		cMan := newConversationManager(time.Millisecond)
		previousConv := cMan.startConversation(msg, "peer")
		cMan.done(previousConv.conversationID)

		conv := cMan.startConversation(msg, "peer")

		assert.NotNil(t, conv)
		assert.Len(t, cMan.conversations, 1)
		assert.Len(t, cMan.lastPeerConversationID, 1)
		assert.Equal(t, conv.conversationID, cMan.lastPeerConversationID["peer"])
	})
	t.Run("previous conversation expired", func(t *testing.T) {
		cMan := newConversationManager(time.Millisecond)
		previousConv := cMan.startConversation(msg, "peer")
		previousConv.createdAt = time.Time{}

		conv := cMan.startConversation(msg, "peer")

		assert.NotNil(t, conv)
		assert.Len(t, cMan.conversations, 2) // expired but not yet evicted
		assert.Len(t, cMan.lastPeerConversationID, 1)
		assert.Equal(t, conv.conversationID, cMan.lastPeerConversationID["peer"])
		assert.NotEqual(t, conv.conversationID, previousConv.conversationID)
	})
	t.Run("one conversation per peer allowed", func(t *testing.T) {
		cMan := newConversationManager(time.Millisecond)
		_ = cMan.startConversation(msg, "other peer")

		conv := cMan.startConversation(msg, "peer")

		assert.NotNil(t, conv)
		assert.Len(t, cMan.conversations, 2)
		assert.Len(t, cMan.lastPeerConversationID, 2)
	})
}

func TestConversationManager_done(t *testing.T) {
	cMan := newConversationManager(time.Millisecond)
	envelope := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{},
	}
	c := cMan.startConversation(envelope, "peerID")

	cMan.done(c.conversationID)

	assert.Len(t, cMan.conversations, 0)
}

func TestEnvelope_TransactionList_ParseTransactions(t *testing.T) {
	tx1, _, _ := dag.CreateTestTransaction(1)
	tx2, _, _ := dag.CreateTestTransaction(2)

	tl := Envelope_TransactionList{TransactionList: &TransactionList{
		Transactions: []*Transaction{
			{
				Data: tx1.Data(),
			},
			{
				Data: tx2.Data(),
			},
		},
	}}

	t.Run("ok", func(t *testing.T) {
		transactions, err := tl.parseTransactions(handlerData{})
		assert.NoError(t, err)
		assert.Len(t, transactions, 2)
		assert.Contains(t, transactions, tx1)
		assert.Contains(t, transactions, tx2)
	})

	t.Run("ok - cached", func(t *testing.T) {
		data := handlerData{}
		_, err := tl.parseTransactions(data)
		assert.NoError(t, err)
		txs, err := Envelope_TransactionList{}.parseTransactions(data) // should take parsed TXs from data
		assert.NoError(t, err)
		assert.Len(t, txs, 2)
	})

	t.Run("error - parse failure", func(t *testing.T) {
		data := handlerData{}
		txs, err := Envelope_TransactionList{TransactionList: &TransactionList{Transactions: []*Transaction{
			{
				Data: tx1.Data(),
			},
			{
				Data: []byte("invalid"),
			},
		}}}.parseTransactions(data)
		assert.Error(t, err)
		assert.Empty(t, txs)
	})
}

func TestConversationManager_checkTransactionRangeQuery(t *testing.T) {
	start := uint32(0)
	end := uint32(1)
	tx1, _, _ := dag.CreateTestTransaction(1)      // LC = 0
	tx2, _, _ := dag.CreateTestTransaction(2, tx1) // LC = 1
	cMan := newConversationManager(time.Millisecond)
	envelope := &Envelope_TransactionRangeQuery{
		TransactionRangeQuery: &TransactionRangeQuery{
			Start: start,
			End:   end,
		},
	}

	t.Run("ok", func(t *testing.T) {
		c := cMan.startConversation(envelope, "ok")
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Data: tx1.Data(),
					},
				},
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.NoError(t, err)
		assert.NotNil(t, c)
	})
	t.Run("error - TX LC out of requested range", func(t *testing.T) {
		t.Skip()
		c := cMan.startConversation(envelope, "error - TX LC out of requested range")
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Data: tx1.Data(),
					},
					{
						Data: tx2.Data(),
					},
				},
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.EqualError(t, err, "TX is not within the requested range (tx="+tx2.Ref().String()+")")
		assert.Nil(t, c)
	})
}

func TestConversationManager_checkTransactionListQuery(t *testing.T) {
	tx1, _, _ := dag.CreateTestTransaction(1)
	tx2, _, _ := dag.CreateTestTransaction(2)
	cMan := newConversationManager(time.Millisecond)
	request := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{
			Refs: [][]byte{tx1.Ref().Slice()},
		},
	}

	t.Run("ok", func(t *testing.T) {
		c := cMan.startConversation(request, "ok")
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Data: tx1.Data(),
					},
				},
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("error - unknown conversation ID", func(t *testing.T) {
		cid := conversationID("9dbacbabf0c6413591f7553ff4348753")
		_ = cMan.startConversation(request, "error - unknown conversation ID")
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: cid.slice(),
				Transactions: []*Transaction{
					{
						Data: tx1.Data(),
					},
				},
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.EqualError(t, err, "unknown or expired conversation (id=9dbacbabf0c6413591f7553ff4348753)")
		assert.Nil(t, c)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		c := cMan.startConversation(request, "error - invalid response")
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Data: tx1.Data(),
					},
					{
						Data: tx2.Data(),
					},
				},
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.ErrorContains(t, err, "response contains non-requested transaction")
		assert.NotNil(t, c)
	})
}

func TestConversationManager_checkState(t *testing.T) {
	cMan := newConversationManager(time.Millisecond)
	request := &Envelope_State{
		State: &State{
			LC: 5,
		},
	}

	t.Run("ok", func(t *testing.T) {
		c := cMan.startConversation(request, "ok")
		response := &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{
				ConversationID: c.conversationID.slice(),
				LC:             8,
				LCReq:          5,
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.NoError(t, err)
		assert.NotNil(t, c)
	})

	t.Run("error - unknown conversation ID", func(t *testing.T) {
		cid := conversationID("9dbacbabf0c6413591f7553ff4348753")
		_ = cMan.startConversation(request, "error - unknown conversation ID")
		response := &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{
				ConversationID: cid.slice(),
				LC:             8,
				LCReq:          5,
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.EqualError(t, err, "unknown or expired conversation (id=9dbacbabf0c6413591f7553ff4348753)")
		assert.Nil(t, c)
	})

	t.Run("error - invalid response", func(t *testing.T) {
		c := cMan.startConversation(request, "error - invalid response")
		response := &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{
				ConversationID: c.conversationID.slice(),
				LC:             8,
				LCReq:          8,
			},
		}

		c, err := cMan.check(response, handlerData{})

		assert.ErrorContains(t, err, "TransactionSet.LCReq is not equal to requested value (requested=5, received=8)")
		assert.NotNil(t, c)
	})
}
