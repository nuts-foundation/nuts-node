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
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

var maxValidity = 30 * time.Second

// handlerData contains contextual data produced and consumed by a message handler.
// It is used to cache expensive data (e.g. parsed transactions) that are used multiple times within a handler,
// but cannot be shared directly due to interface incompatibility.
type handlerData map[interface{}]interface{}

type conversationID string

var errIncorrectEnvelopeType = errors.New("checking wrong envelope type")

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
	conversationID conversationID
	// expiry is the time the conversation expires.
	expiry           time.Time
	conversationData checkable
}

type blockable interface {
	checkable
	blockingConversation()
}

type checkable interface {
	conversationable
	checkResponse(envelope isEnvelope_Message, data handlerData) error
}

type conversationable interface {
	isEnvelope_Message
	setConversationID(cid conversationID)
	conversationID() []byte
}

type conversationManager struct {
	mutex                  sync.RWMutex
	conversations          map[string]*conversation
	validity               time.Duration
	lastPeerConversationID map[string]conversationID
}

func newConversationManager(validity time.Duration) *conversationManager {
	return &conversationManager{
		conversations:          map[string]*conversation{},
		validity:               validity,
		lastPeerConversationID: map[string]conversationID{},
	}
}

func (cMan *conversationManager) start(ctx context.Context) {
	done := ctx.Done()

	go func() {
		timer := time.NewTimer(cMan.validity)
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				cMan.evict()
			}
		}
	}()
}

func (cMan *conversationManager) evict() {
	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	for k, v := range cMan.conversations {
		if v.expiry.Before(time.Now()) {
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

func (cMan *conversationManager) resetTimeout(cid conversationID) {
	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	if conversation, exists := cMan.conversations[cid.String()]; exists {
		conversation.expiry = time.Now().Add(cMan.validity)
	}
}

// startConversation sets a conversationID on the envelope and stores the conversation
func (cMan *conversationManager) startConversation(msg checkable, peer transport.Peer) *conversation {
	cid := newConversationID()

	msg.setConversationID(cid)
	newConversation := &conversation{
		conversationID:   cid,
		expiry:           time.Now().Add(cMan.validity),
		conversationData: msg,
	}

	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	if _, ok := msg.(blockable); ok {
		if cMan.hasActiveConversation(peer) {
			return nil
		}
		cMan.lastPeerConversationID[peer.Key()] = cid
	}

	cMan.conversations[cid.String()] = newConversation

	return newConversation
}

func (cMan *conversationManager) hasActiveConversation(peer transport.Peer) bool {
	if lastPeerConv, ok := cMan.lastPeerConversationID[peer.Key()]; ok {
		if conversation, ok := cMan.conversations[lastPeerConv.String()]; ok {
			if conversation.expiry.After(time.Now()) {
				return true
			}
		}
	}
	return false
}

func (cMan *conversationManager) check(envelope conversationable, data handlerData) (*conversation, error) {
	cidBytes := envelope.conversationID()
	cid := conversationID(cidBytes)

	cMan.mutex.RLock()
	defer cMan.mutex.RUnlock()

	if req, ok := cMan.conversations[cid.String()]; !ok {
		return nil, fmt.Errorf("unknown or expired conversation (id=%s)", cid)
	} else {
		return req, req.conversationData.checkResponse(envelope, data)
	}
}

func (envelope *Envelope_TransactionListQuery) setConversationID(cid conversationID) {
	envelope.TransactionListQuery.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionListQuery) conversationID() []byte {
	return envelope.TransactionListQuery.ConversationID
}

func (envelope *Envelope_TransactionListQuery) checkResponse(other isEnvelope_Message, data handlerData) error {
	// envelope type already checked in cMan.check()
	otherEnvelope, ok := other.(*Envelope_TransactionList)
	if !ok {
		return errIncorrectEnvelopeType
	}

	// as map for easy finding
	refs := map[hash.SHA256Hash]bool{}
	for _, bytes := range envelope.TransactionListQuery.Refs {
		ref := hash.FromSlice(bytes)
		refs[ref] = true
	}

	txs, err := otherEnvelope.parseTransactions(data)
	if err != nil {
		return err
	}

	for _, tx := range txs {
		if _, ok := refs[tx.Ref()]; !ok {
			return fmt.Errorf("response contains non-requested transaction (ref=%s)", tx.Ref())
		}
	}

	return nil
}

func (envelope *Envelope_TransactionListQuery) blockingConversation() {}

func (envelope *Envelope_TransactionRangeQuery) setConversationID(cid conversationID) {
	envelope.TransactionRangeQuery.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionRangeQuery) conversationID() []byte {
	return envelope.TransactionRangeQuery.ConversationID
}

func (envelope *Envelope_TransactionRangeQuery) checkResponse(other isEnvelope_Message, data handlerData) error {
	otherEnvelope, ok := other.(*Envelope_TransactionList)
	if !ok {
		return errIncorrectEnvelopeType
	}
	txs, err := otherEnvelope.parseTransactions(data)
	if err != nil {
		return err
	}
	// As per RFC017, every TX in the response must have an LC value within the requested range
	for _, tx := range txs {
		if tx.Clock() < envelope.TransactionRangeQuery.Start || tx.Clock() >= envelope.TransactionRangeQuery.End {
			return fmt.Errorf("TX is not within the requested range (tx=%s)", tx.Ref())
		}
	}
	return nil
}

func (envelope *Envelope_TransactionRangeQuery) blockingConversation() {}

func (envelope *Envelope_TransactionList) setConversationID(cid conversationID) {
	envelope.TransactionList.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionList) conversationID() []byte {
	return envelope.TransactionList.ConversationID
}

// parseTransactions parses the transactions from the message and caches them in the handlerData,
// so subsequent calls to parseTransactions will not parse the transactions again.
func (envelope Envelope_TransactionList) parseTransactions(data handlerData) ([]dag.Transaction, error) {
	type key struct{}
	dataKey := key{}
	cached, ok := data[dataKey].([]dag.Transaction)
	if ok {
		return cached, nil
	}

	var transactions []dag.Transaction
	for _, transaction := range envelope.TransactionList.Transactions {
		tx, err := dag.ParseTransaction(transaction.Data)
		if err != nil {
			return nil, fmt.Errorf("received transaction is invalid: %w", err)
		}
		transactions = append(transactions, tx)
	}

	data[dataKey] = transactions
	return transactions, nil
}

func (envelope *Envelope_State) checkResponse(other isEnvelope_Message, _ handlerData) error {
	// envelope type already checked in cMan.check()
	otherEnvelope, ok := other.(*Envelope_TransactionSet)
	if !ok {
		return errIncorrectEnvelopeType
	}

	if envelope.State.LC != otherEnvelope.TransactionSet.LCReq {
		return fmt.Errorf("TransactionSet.LCReq is not equal to requested value (requested=%d, received=%d)", envelope.State.LC, otherEnvelope.TransactionSet.LCReq)
	}
	return nil
}

func (envelope *Envelope_State) setConversationID(cid conversationID) {
	envelope.State.ConversationID = cid.slice()
}

func (envelope *Envelope_State) conversationID() []byte {
	return envelope.State.ConversationID
}

func (envelope *Envelope_TransactionSet) setConversationID(cid conversationID) {
	envelope.TransactionSet.ConversationID = cid.slice()
}

func (envelope *Envelope_TransactionSet) conversationID() []byte {
	return envelope.TransactionSet.ConversationID
}
