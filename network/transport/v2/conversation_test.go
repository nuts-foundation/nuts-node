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
	"github.com/nuts-foundation/nuts-node/network/dag"
	"testing"
	"time"

	"github.com/google/uuid"
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

	_ = cMan.startConversation(envelope)

	test.WaitFor(t, func() (bool, error) {
		cMan.mutex.Lock()
		defer cMan.mutex.Unlock()
		return len(cMan.conversations) == 0, nil
	}, time.Second, "timeout while waiting for conversations to clear")
}

func TestConversationManager_done(t *testing.T) {
	cMan := newConversationManager(time.Millisecond)
	envelope := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{},
	}
	c := cMan.startConversation(envelope)

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
		transactions, err := tl.ParseTransactions(handlerData{})
		assert.NoError(t, err)
		assert.Len(t, transactions, 2)
		assert.Contains(t, transactions, tx1)
		assert.Contains(t, transactions, tx2)
	})

	t.Run("ok - cached", func(t *testing.T) {
		data := handlerData{}
		_, err := tl.ParseTransactions(data)
		assert.NoError(t, err)
		txs, err := Envelope_TransactionList{}.ParseTransactions(data) // should take parsed TXs from data
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
		}}}.ParseTransactions(data)
		assert.Error(t, err)
		assert.Empty(t, txs)
	})
}

func TestConversationManager_checkTransactionList(t *testing.T) {
	tx1, _, _ := dag.CreateTestTransaction(1)
	tx2, _, _ := dag.CreateTestTransaction(2)
	cMan := newConversationManager(time.Millisecond)
	request := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{
			Refs: [][]byte{tx1.Ref().Slice()},
		},
	}

	t.Run("ok", func(t *testing.T) {
		c := cMan.startConversation(request)
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

		err := cMan.check(response, handlerData{})

		assert.NoError(t, err)
	})

	t.Run("error - unknown conversation ID", func(t *testing.T) {
		cid := conversationID("9dbacbabf0c6413591f7553ff4348753")
		_ = cMan.startConversation(request)
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

		err := cMan.check(response, handlerData{})

		assert.EqualError(t, err, "unknown or expired conversation (id=9dbacbabf0c6413591f7553ff4348753)")
	})

	t.Run("error - invalid response", func(t *testing.T) {
		c := cMan.startConversation(request)
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

		err := cMan.check(response, handlerData{})

		assert.ErrorContains(t, err, "response contains non-requested transaction")
	})
}
