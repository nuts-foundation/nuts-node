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

package network

import (
	crypto2 "crypto"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// Transactions is the interface that defines the API for creating, reading and subscribing to Nuts Network transactions.
type Transactions interface {
	// Subscribe makes a subscription for the specified transaction type. The receiver is called when a transaction
	// is received for the specified type.
	Subscribe(payloadType string, receiver dag.Receiver)
	// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
	// nil is returned.
	GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error)
	// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
	GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error)
	// CreateTransaction creates a new transaction with the specified payload, and signs it using the specified key.
	// If the key should be inside the transaction (instead of being referred to) `attachKey` should be true.
	CreateTransaction(payloadType string, payload []byte, signingKeyID string, attachKey crypto2.PublicKey, timestamp time.Time, fieldsOpts ...dag.FieldOpt) (dag.Transaction, error)
	// ListTransactions returns all transactions known to this Network instance.
	ListTransactions() ([]dag.Transaction, error)
	// Walk walks the DAG starting at the root, calling `visitor` for every transaction.
	Walk(visitor dag.Visitor) error
}
