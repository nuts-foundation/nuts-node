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
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
)

func TestConversationID(t *testing.T) {
	hexUUID := "bd7baaa8f3244d229dc6512d02a88336"

	t.Run("new creates a v4 uuid", func(t *testing.T) {
		cid := newConversationID()

		u := uuid.UUID(cid)

		assert.Equal(t, uuid.Version(4), u.Version())
	})

	t.Run("String returns hex encoding", func(t *testing.T) {
		cid := newConversationID()

		s := cid.String()

		assert.Len(t, s, 32)
	})

	t.Run("slice() returns bytes", func(t *testing.T) {
		cid := newConversationID()

		bytes := cid.slice()

		assert.Len(t, bytes, 16)
	})

	t.Run("ok - parseConversationID", func(t *testing.T) {
		bytes, _ := hex.DecodeString(hexUUID)

		cid, err := parseConversationID(bytes)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, hexUUID, cid.String())
	})

	t.Run("error - parseConversationID", func(t *testing.T) {
		_, err := parseConversationID([]byte{})

		assert.Error(t, err)
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

	_ = cMan.conversationFromEnvelope(envelope)

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
	c := cMan.conversationFromEnvelope(envelope)

	cMan.done(c.conversationID)

	assert.Len(t, cMan.conversations, 0)
}

func TestConversationManager_checkTransactionList(t *testing.T) {
	ref := hash.EmptyHash().Slice()
	cMan := newConversationManager(time.Millisecond)
	request := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{
			Refs: [][]byte{ref},
		},
	}

	t.Run("ok", func(t *testing.T) {
		c := cMan.conversationFromEnvelope(request)
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Hash: ref,
					},
				},
			},
		}

		err := cMan.check(response)

		assert.NoError(t, err)
	})

	t.Run("error - invalid conversation ID", func(t *testing.T) {
		_ = cMan.conversationFromEnvelope(request)
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				Transactions: []*Transaction{
					{
						Hash: ref,
					},
				},
			},
		}

		err := cMan.check(response)

		assert.EqualError(t, err, "failed to parse conversationID: invalid UUID (got 0 bytes)")
	})

	t.Run("error - unknown conversation ID", func(t *testing.T) {
		u, _ := uuid.Parse("9dbacbabf0c6413591f7553ff4348753")
		cid := conversationID(u)
		_ = cMan.conversationFromEnvelope(request)
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: cid.slice(),
				Transactions: []*Transaction{
					{
						Hash: ref,
					},
				},
			},
		}

		err := cMan.check(response)

		assert.EqualError(t, err, "unknown or expired conversation (id=9dbacbabf0c6413591f7553ff4348753)")
	})

	t.Run("error - invalid response", func(t *testing.T) {
		ref2 := hash.SHA256Sum([]byte{0}).Slice()
		c := cMan.conversationFromEnvelope(request)
		response := &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: c.conversationID.slice(),
				Transactions: []*Transaction{
					{
						Hash: ref,
					},
					{
						Hash: ref2,
					},
				},
			},
		}

		err := cMan.check(response)

		assert.EqualError(t, err, "response contains non-requested transaction (ref=6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d)")
	})
}
