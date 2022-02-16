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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

var maxValidity = 30 * time.Second

type conversationID uuid.UUID

func newConversationID() conversationID {
	return conversationID(uuid.New())
}

func parseConversationID(bytes []byte) (cid conversationID, err error) {
	var u uuid.UUID
	u, err = uuid.FromBytes(bytes)
	if err != nil {
		return
	}
	cid = conversationID(u)
	return
}

func (cid conversationID) slice() []byte {
	// error not possible when marshalling
	bytes, _ := uuid.UUID(cid).MarshalBinary()
	return bytes
}

func (cid conversationID) String() string {
	return hex.EncodeToString(cid.slice())
}

type conversation interface {
	checkResponse(envelop isEnvelope_Message) error
	conversationID() conversationID
	createdAt() time.Time
}

type conversationManager struct {
	mutex         sync.RWMutex
	conversations map[string]conversation
	validity      time.Duration
}

func newConversationManager(validity time.Duration) *conversationManager {
	return &conversationManager{
		conversations: map[string]conversation{},
		validity:      validity,
	}
}

func (cMan *conversationManager) start(ctx context.Context) {
	done := ctx.Done()

	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.Tick(cMan.validity):
				cMan.evict()
			}
		}
	}()
}

func (cMan *conversationManager) evict() {
	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	for k, v := range cMan.conversations {
		createdAt := v.createdAt()
		if createdAt.Add(cMan.validity).Before(time.Now()) {
			delete(cMan.conversations, k)
		}
	}
}

func (cMan *conversationManager) done(cid conversationID) {
	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	delete(cMan.conversations, cid.String())
}

// conversationFromEnvelop sets a conversationID on the envelop and stores the conversation
func (cMan *conversationManager) conversationFromEnvelop(envelop isEnvelope_Message) (newConversation conversation) {
	cid := newConversationID()

	switch t := envelop.(type) {
	case *Envelope_TransactionListQuery:
		t.TransactionListQuery.ConversationID = cid.slice()
		newConversation = transactionListConversation{
			id:  cid,
			at:  time.Now(),
			msg: t,
		}
	default:
		return
	}

	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	cMan.conversations[cid.String()] = newConversation

	return
}

func (cMan *conversationManager) check(envelop isEnvelope_Message) error {
	var cidBytes []byte

	switch t := envelop.(type) {
	case *Envelope_TransactionList:
		cidBytes = t.TransactionList.ConversationID
	default:
		return errors.New("invalid response msg type")
	}

	cid, err := parseConversationID(cidBytes)
	if err != nil {
		return fmt.Errorf("failed to parse conversationID: %w", err)
	}

	cMan.mutex.RLock()
	defer cMan.mutex.RUnlock()

	if req, ok := cMan.conversations[cid.String()]; !ok {
		return fmt.Errorf("unknown conversation (id=%s)", cid)
	} else {
		return req.checkResponse(envelop)
	}
}

type transactionListConversation struct {
	id  conversationID
	at  time.Time
	msg *Envelope_TransactionListQuery
}

func (c transactionListConversation) checkResponse(envelop isEnvelope_Message) error {
	// envelop type already checked in cMan.check()
	otherEnvelop := envelop.(*Envelope_TransactionList)

	payloadRequest := c.msg.TransactionListQuery
	payloadResponse := otherEnvelop.TransactionList

	// as map for easy finding
	refs := map[string]bool{}
	for _, bytes := range payloadRequest.Refs {
		ref := hash.FromSlice(bytes)
		refs[ref.String()] = true
	}

	for _, transaction := range payloadResponse.Transactions {
		// ref is the sha256 of the transaction payload
		ref := hash.FromSlice(transaction.Hash)
		if _, ok := refs[ref.String()]; !ok {
			return fmt.Errorf("response contains non-requested transaction (ref=%s)", ref.String())
		}
	}

	return nil
}

func (c transactionListConversation) conversationID() conversationID {
	return c.id
}

func (c transactionListConversation) createdAt() time.Time {
	return c.at
}
