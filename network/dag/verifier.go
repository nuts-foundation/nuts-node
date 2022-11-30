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
type Verifier func(transaction Transaction) error

// NewTransactionSignatureVerifier creates a transaction verifier that checks the signature of the transaction.
// It uses the given KeyResolver to resolves keys that aren't embedded in the transaction.
func newTransactionSignatureVerifier(resolver types.KeyResolver) Verifier {
	return func(transaction Transaction) error {
		var signingKey crypto2.PublicKey
		if transaction.SigningKey() != nil {
			if err := transaction.SigningKey().Raw(&signingKey); err != nil {
				return err
			}
		} else {
			pk, err := resolver.ResolvePublicKey(transaction.SigningKeyID(), transaction.Previous())
			if err != nil {
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
func newPrevTransactionsVerifier(graph *dag) Verifier {
	return func(tx Transaction) error {
		// “New transaction additions MUST refer [prevs] to a
		// transaction with the highest lc value present within the
		// applicable graph. When multiple transactions match the
		// highest lc value present, then only a single one of them
		// [arbitrary] SHOULD be refered to.”
		// — Nuts RFC004
		previousClock := tx.Clock() - 1
		var containsPreviousClock bool
		for _, hash := range tx.Previous() {
			p, err := graph.txByHash(hash)
			switch {
			case err == nil:
				if p.Clock() == previousClock {
					containsPreviousClock = true
				}
			case errors.Is(err, ErrTransactionNotFound):
				return ErrPreviousTransactionMissing
			default:
				return err
			}
		}
		if !containsPreviousClock {
			return ErrInvalidLamportClockValue
		}
		return nil
	}
}
