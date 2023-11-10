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
	"context"
	"errors"
	"fmt"

	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nuts-foundation/nuts-node/crypto"
)

const errSigningTransactionFmt = "error while signing transaction: %w"

// TransactionSigner defines functions to sign transactions.
type TransactionSigner interface {
	// Sign signs the unsigned transaction, including the signingTime parameter as header.
	Sign(ctx context.Context, input UnsignedTransaction, signingTime time.Time) (Transaction, error)
}

// NewTransactionSigner creates a TransactionSigner that signs the transaction using the given key.
// The public key is included in the signed transaction if attach == true. If not attached, the `kid` header is added which refers to the ID
// of the used key.
func NewTransactionSigner(signer crypto.JWTSigner, key crypto.Key, attach bool) TransactionSigner {
	return &transactionSigner{
		key:    key,
		attach: attach,
		signer: signer,
	}
}

type transactionSigner struct {
	attach bool
	key    crypto.Key
	signer crypto.JWTSigner
}

func (d transactionSigner) Sign(ctx context.Context, input UnsignedTransaction, signingTime time.Time) (Transaction, error) {
	// Preliminary sanity checks
	if signingTime.IsZero() {
		return nil, errors.New("signing time is zero")
	}
	if tx, ok := input.(Transaction); ok && !tx.SigningTime().IsZero() {
		return nil, errors.New("transaction is already signed")
	}

	var key jwk.Key
	var err error
	if d.attach {
		key, err = jwk.FromRaw(d.key.Public())
		if err != nil {
			return nil, fmt.Errorf(errSigningTransactionFmt, err)
		}
		key.Set(jwk.KeyIDKey, d.key.KID())
	}

	prevsAsString := make([]string, len(input.Previous()))
	for i, prev := range input.Previous() {
		prevsAsString[i] = prev.String()
	}
	normalizedMoment := signingTime.UTC()
	headerMap := map[string]interface{}{
		jws.ContentTypeKey: input.PayloadType(),
		jws.CriticalKey:    []string{signingTimeHeader, versionHeader, previousHeader, lamportClockHeader},
		signingTimeHeader:  normalizedMoment.Unix(),
		previousHeader:     prevsAsString,
		versionHeader:      input.Version(),
		lamportClockHeader: input.Clock(),
	}

	if input.PAL() != nil {
		headerMap[palHeader] = input.PAL()
	}

	if d.attach {
		headerMap[jws.JWKKey] = key
	} else {
		headerMap[jws.KeyIDKey] = d.key.KID()
	}

	data, err := d.signer.SignJWS(ctx, []byte(input.PayloadHash().String()), headerMap, d.key, false)
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	signedTransaction, err := ParseTransaction([]byte(data))
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	return signedTransaction, nil
}
