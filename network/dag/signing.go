package dag

import (
	"errors"
	"fmt"

	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto"
)

const errSigningTransactionFmt = "error while signing transaction: %w"

// TransactionSigner defines functions to sign transactions.
type TransactionSigner interface {
	// Sign signs the unsigned transaction, including the signingTime parameter as header.
	Sign(input UnsignedTransaction, signingTime time.Time) (Transaction, error)
}

// NewTransactionSigner creates a TransactionSigner that signs the transaction using the given key.
// The public key is included in the signed transaction if attach == true. If not attached, the `kid` header is added which refers to the ID
// of the used key.
func NewTransactionSigner(key crypto.KeySelector, attach bool) TransactionSigner {
	return &transactionSigner{
		key:    key,
		attach: attach,
	}
}

type transactionSigner struct {
	attach bool
	key    crypto.KeySelector
}

func (d transactionSigner) Sign(input UnsignedTransaction, signingTime time.Time) (Transaction, error) {
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
		key, err = jwk.New(d.key.Public())
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
		jws.CriticalKey:    []string{signingTimeHeader, versionHeader, previousHeader},
		signingTimeHeader:  normalizedMoment.Unix(),
		previousHeader:     prevsAsString,
		versionHeader:      input.Version(),
	}
	if d.attach {
		headerMap[jws.CriticalKey] = append(headerMap[jws.CriticalKey].([]string), jws.JWKKey)
		headerMap[jws.JWKKey] = key
	} else {
		headerMap[jws.CriticalKey] = append(headerMap[jws.CriticalKey].([]string), jws.KeyIDKey)
		headerMap[jws.KeyIDKey] = d.key.KID()
	}

	data, err := crypto.SignJWS([]byte(input.PayloadHash().String()), headerMap, d.key.Signer())
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	signedTransaction, err := ParseTransaction([]byte(data))
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	return signedTransaction, nil
}
