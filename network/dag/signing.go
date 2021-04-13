package dag

import (
	crypto2 "crypto"
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

// NewAttachedJWKTransactionSigner creates a TransactionSigner that signs the transaction using the given key.
// The public key (identified by `kid`) is added to the signed transaction as `jwk` header. The public key is resolved
// using the given resolver and the `kid` parameter.
func NewAttachedJWKTransactionSigner(jwsSigner crypto.JWSSigner, kid string, key crypto2.PublicKey) TransactionSigner {
	return &transactionSigner{
		signer: jwsSigner,
		kid:    kid,
		attach: true,
		key:    key,
	}
}

// NewTransactionSigner creates a TransactionSigner that signs the transaction using the given key.
// The public key is not included in the signed transaction, instead the `kid` header is added which must refer to the ID
// of the used key.
func NewTransactionSigner(jwsSigner crypto.JWSSigner, kid string) TransactionSigner {
	return &transactionSigner{
		signer: jwsSigner,
		kid:    kid,
		attach: false,
	}
}

type transactionSigner struct {
	attach bool
	kid    string
	signer crypto.JWSSigner
	key    crypto2.PublicKey
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
		key, err = jwk.New(d.key)
		if err != nil {
			return nil, fmt.Errorf(errSigningTransactionFmt, err)
		}
		key.Set(jwk.KeyIDKey, d.kid)
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
		headerMap[jws.KeyIDKey] = d.kid
	}

	data, err := d.signer.SignJWS([]byte(input.PayloadHash().String()), headerMap, d.kid)
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	signedTransaction, err := ParseTransaction([]byte(data))
	if err != nil {
		return nil, fmt.Errorf(errSigningTransactionFmt, err)
	}
	return signedTransaction, nil
}
