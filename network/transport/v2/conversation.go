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
	"github.com/nuts-foundation/nuts-node/network/dag"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
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
	conversationID   conversationID
	createdAt        time.Time
	conversationData checkable
	// additionalInfo can be used to check if a conversation is done
	additionalInfo map[string]interface{}
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
func (cMan *conversationManager) startConversation(msg checkable) *conversation {
	cid := newConversationID()

	msg.setConversationID(cid)
	newConversation := &conversation{
		conversationID:   cid,
		createdAt:        time.Now(),
		conversationData: msg,
		additionalInfo:   map[string]interface{}{},
	}

	cMan.mutex.Lock()
	defer cMan.mutex.Unlock()

	cMan.conversations[cid.String()] = newConversation

	return newConversation
}

func (cMan *conversationManager) check(envelope conversationable, data handlerData) error {
	cidBytes := envelope.conversationID()
	cid := conversationID(cidBytes)

	cMan.mutex.RLock()
	defer cMan.mutex.RUnlock()

	if req, ok := cMan.conversations[cid.String()]; !ok {
		return fmt.Errorf("unknown or expired conversation (id=%s)", cid)
	} else {
		return req.conversationData.checkResponse(envelope, data)
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
	// As per RFC017, every TX in the response must have a LC value within the requested range
	for _, rawTX := range otherEnvelope.TransactionList.Transactions {
		tx, err := dag.ParseTransaction(rawTX.Data)
		if err != nil {
			return fmt.Errorf("response contains an invalid transaction: %w", err)
		}
		if tx.Clock() < envelope.TransactionRangeQuery.Start || tx.Clock() >= envelope.TransactionRangeQuery.End {
			return fmt.Errorf("TX is not within the requested range (tx=%s)", tx.Ref())
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
