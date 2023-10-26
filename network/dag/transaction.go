/*
 * Nuts node
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
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// Version defines a type for distributed transaction format version.
type Version int

const currentVersion = 2

var allowedVersion = []Version{1, 2}

const (
	signingTimeHeader  = "sigt"
	versionHeader      = "ver"
	previousHeader     = "prevs"
	palHeader          = "pal"
	lamportClockHeader = "lc"
)

var allowedAlgos = []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512, jwa.ES256K, jwa.PS256, jwa.PS384, jwa.PS512, jwa.EdDSA}

var errInvalidPayloadType = errors.New("payload type must be formatted as MIME type")
var errInvalidPrevs = errors.New("prevs contains an empty hash")
var unableToParseTransactionErrFmt = "unable to parse transaction: %w"
var transactionNotValidErrFmt = "transaction validation failed: %w"
var missingHeaderErrFmt = "missing %s header"
var invalidHeaderErrFmt = "invalid %s header"

// UnsignedTransaction holds the base properties of a transaction which can be signed to create a Transaction.
type UnsignedTransaction interface {
	NetworkHeader
	Addressable
	PayloadReferencer

	// Clock returns the Lamport clock value
	Clock() uint32
}

// PayloadReferencer allows implementers to reference to a payload.
// It provides an uniform interface to payload properties such as the type and the hash.
type PayloadReferencer interface {
	// PayloadHash returns the hash of the payload of the transaction.
	PayloadHash() hash.SHA256Hash

	// PayloadType returns the MIME-formatted type of the payload. It must contain the context and specific type of the
	// payload, e.g. 'registry/endpoint'.
	PayloadType() string
}

// NetworkHeader groups methods for working with a transaction header.
type NetworkHeader interface {
	// Previous returns the references of the previous transactions this transaction points to.
	Previous() []hash.SHA256Hash
	// Version returns the version number of the distributed transaction format.
	Version() Version
}

// Signable groups a set of functions to access information about a implementors signature.
type Signable interface {
	// SigningKey returns the key that was used to sign the transaction as JWK.
	// If this field is not set SigningKeyID must be used to resolve the signing key.
	SigningKey() jwk.Key
	// SigningKeyID returns the ID of the key that was used to sign the transaction. It can be used to look up the key.
	SigningKeyID() string
	// SigningTime returns the time that the transaction was signed.
	SigningTime() time.Time
	// SigningAlgorithm returns the name of the JOSE signing algorithm that was used to sign the transaction.
	SigningAlgorithm() string
}

// Referencable contains the Ref function which allows implementors to return a unique reference
type Referencable interface {
	// Ref returns a unique sha256 hash of the implementing object.
	Ref() hash.SHA256Hash
}

// Addressable contains the Pal function which allows returning the addresses of the recipients
type Addressable interface {
	// PAL contains the encrypted addresses of the participants
	PAL() [][]byte
}

// Transaction defines a signed distributed transaction as described by RFC004 - Distributed Transaction Format.
type Transaction interface {
	UnsignedTransaction
	Signable
	Referencable
	Addressable
	json.Marshaler
	// Data returns the byte representation of this transaction which can be used for transport.
	Data() []byte
}

// NewTransaction creates a new unsigned transaction. Parameters payload and payloadType can't be empty, but prevs is optional.
// Prevs must not contain empty or invalid hashes. Duplicate prevs will be removed when given.
// The pal byte slice (may be nil) holds the encrypted recipient address, if it is a private transaction.
func NewTransaction(payload hash.SHA256Hash, payloadType string, prevs []hash.SHA256Hash, pal EncryptedPAL, lamportClock uint32) (UnsignedTransaction, error) {
	if !ValidatePayloadType(payloadType) {
		return nil, errInvalidPayloadType
	}
	for _, prev := range prevs {
		if prev.Empty() {
			return nil, errInvalidPrevs
		}
	}

	// deduplicate prevs
	deduplicated := make([]hash.SHA256Hash, 0)
	for _, prev := range prevs {
		found := false
		for _, dd := range deduplicated {
			if dd.Equals(prev) {
				found = true
				break
			}
		}
		if !found {
			deduplicated = append(deduplicated, prev)
		}
	}

	result := transaction{
		payload:      payload,
		payloadType:  payloadType,
		version:      currentVersion,
		pal:          pal,
		lamportClock: lamportClock,
	}
	if len(deduplicated) > 0 {
		result.prevs = deduplicated
	}
	return &result, nil
}

// ValidatePayloadType checks whether the payload type is valid according to RFC004.
func ValidatePayloadType(payloadType string) bool {
	return strings.Contains(payloadType, "/")
}

type transaction struct {
	prevs            []hash.SHA256Hash
	payload          hash.SHA256Hash
	payloadType      string
	signingKey       jwk.Key
	signingKeyID     string
	signingTime      time.Time
	signingAlgorithm jwa.SignatureAlgorithm
	version          Version
	lamportClock     uint32
	data             []byte
	ref              hash.SHA256Hash
	pal              [][]byte
}

func (d transaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d.Data()))
}

func (d transaction) PAL() [][]byte {
	return d.pal
}

func (d transaction) Data() []byte {
	return d.data
}

func (d transaction) SigningKey() jwk.Key {
	return d.signingKey
}

func (d transaction) SigningKeyID() string {
	return d.signingKeyID
}

func (d transaction) SigningTime() time.Time {
	return d.signingTime
}

func (d transaction) SigningAlgorithm() string {
	return d.signingAlgorithm.String()
}

func (d transaction) PayloadType() string {
	return d.payloadType
}

func (d transaction) PayloadHash() hash.SHA256Hash {
	return d.payload
}

func (d transaction) Previous() []hash.SHA256Hash {
	return d.prevs
}

func (d transaction) Ref() hash.SHA256Hash {
	return d.ref
}

func (d transaction) Version() Version {
	return d.version
}

func (d transaction) Clock() uint32 {
	return d.lamportClock
}

func (d *transaction) setData(data []byte) {
	d.data = data
	d.ref = hash.SHA256Sum(d.data)
}
