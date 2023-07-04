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

package dag

import (
	crypto2 "crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrPreviousTransactionMissing indicates one or more of the previous transactions (which the transaction refers to)
// is missing.
var ErrPreviousTransactionMissing = errors.New("transaction is referring to non-existing previous transaction")

// ErrInvalidLamportClockValue indicates the lamport clock value for the transaction is wrong.
var ErrInvalidLamportClockValue = errors.New("transaction has an invalid lamport clock value")

// Verifier defines the API of a DAG verifier, used to check the validity of a transaction.
type Verifier func(tx stoabs.ReadTx, transaction Transaction) error

// NewTransactionSignatureVerifier creates a transaction verifier that checks the signature of the transaction.
// It uses the given KeyResolver to resolves keys that aren't embedded in the transaction.
func NewTransactionSignatureVerifier(resolver types.KeyResolver) Verifier {
	return func(_ stoabs.ReadTx, transaction Transaction) error {
		var signingKey crypto2.PublicKey
		if transaction.SigningKey() != nil {
			if err := transaction.SigningKey().Raw(&signingKey); err != nil {
				return err
			}
		} else {
			if transaction.Previous()[0].String() == "3ccd4a4dc70d0c2245e09623373a3ec4678d0ad961aed42c5c92a32fa8b6ecc8" {
				println("previous transaction is genesis")
			}
			pk, err := resolver.ResolvePublicKey(transaction.SigningKeyID(), transaction.Previous())
			if err != nil {
				for _, prev := range transaction.Previous() {
					println(prev.String())
				}
				return fmt.Errorf("unable to verify transaction signature, can't resolve key by TX ref (kid=%s, tx=%s): %w", transaction.SigningKeyID(), transaction.Ref().String(), err)
			}
			signingKey = pk
		}
		// TODO: jws.Verify parses the JWS again, which we already did when parsing the transaction. If we want to optimize
		// this we need to implement a custom verifier.
		_, err := jws.Verify(transaction.Data(), jwa.SignatureAlgorithm(transaction.SigningAlgorithm()), signingKey)
		return err
	}
}

// NewPrevTransactionsVerifier creates a transaction verifier that asserts that all previous transactions are known.
// It also checks if the lamportClock value is correct (if given).
func NewPrevTransactionsVerifier() Verifier {
	return func(tx stoabs.ReadTx, transaction Transaction) error {
		highestLamportClock := -1
		for _, prev := range transaction.Previous() {
			previousTransaction, err := getTransaction(prev, tx)
			if err != nil {
				if errors.Is(err, ErrTransactionNotFound) {
					return ErrPreviousTransactionMissing
				}
				return err
			}
			if int(previousTransaction.Clock()) >= highestLamportClock {
				highestLamportClock = int(previousTransaction.Clock())
			}
		}

		if int(transaction.Clock()) != highestLamportClock+1 {
			return ErrInvalidLamportClockValue
		}

		return nil
	}
}
