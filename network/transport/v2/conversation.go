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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

var maxValidity = 30 * time.Second

type conversationID string

func newConversationID() conversationID {
	return conversationID(uuid.New().String())
}

func (cid conversationID) slice() []byte {
	return []byte(cid)
}

func (cid conversationID) String() string {
	return string(cid)
}

type conversation struct {
	conversationID   conversationID
	createdAt        time.Time
	conversationData checkable
	// additionalInfo can be used to check if a conversation is done
	additionalInfo map[string]interface{}
}

type checkable interface {
	conversationable
	checkResponse(envelope isEnvelope_Message) error
}

type conversationable interface {
	setConversationID(cid conversationID)
	conversationID() []byte
}

type conversationManager struct {
	mutex         sync.RWMutex
	conversations map[string]*conversation
	validity      time.Duration
}

func newConversationManager(validity time.Duration) *conversationManager {
	return &conversationManager{
		conversations: map[string]*conversation{},
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
		createdAt := v.createdAt
		if createdAt.Add(cMan.validity).Before(time.Now()) {
			delete(cMan.conversations, k)
		}
	}
}

// done ends the conversation. In the case when multiple messages are to be expected (pagination) then done() should be called after the last message.
func (cMan *conversationManager) done(cid conversationID) {
	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	delete(cMan.conversations, cid.String())
}

// startConversation sets a conversationID on the envelope and stores the conversation
func (cMan *conversationManager) startConversation(envelope checkable) *conversation {
	cid := newConversationID()

	envelope.setConversationID(cid)
	newConversation := &conversation{
		conversationID:   cid,
		createdAt:        time.Now(),
		conversationData: envelope,
		additionalInfo:   map[string]interface{}{},
	}

	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	cMan.conversations[cid.String()] = newConversation

	return newConversation
}

func (cMan *conversationManager) check(envelope isEnvelope_Message) error {
	otherEnvelope, ok := envelope.(conversationable)
	if !ok {
		return errors.New("expecting envelope to contain be a conversation response type message")
	}

	cidBytes := otherEnvelope.conversationID()
	cid := conversationID(cidBytes)

	cMan.mutex.RLock()
	defer cMan.mutex.RUnlock()

	if req, ok := cMan.conversations[cid.String()]; !ok {
		return fmt.Errorf("unknown or expired conversation (id=%s)", cid)
	} else {
		return req.conversationData.checkResponse(envelope)
	}
}

func (envelope *Envelope_TransactionListQuery) setConversationID(cid conversationID) {
	envelope.TransactionListQuery.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionListQuery) conversationID() []byte {
	return envelope.TransactionListQuery.ConversationID
}

func (envelope *Envelope_TransactionListQuery) checkResponse(other isEnvelope_Message) error {
	// envelope type already checked in cMan.check()
	otherEnvelope, ok := other.(*Envelope_TransactionList)
	if !ok {
		return errors.New("checking wrong envelope type")
	}

	payloadRequest := envelope.TransactionListQuery
	payloadResponse := otherEnvelope.TransactionList

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

func (envelope *Envelope_TransactionList) setConversationID(cid conversationID) {
	envelope.TransactionList.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionList) conversationID() []byte {
	return envelope.TransactionList.ConversationID
}
