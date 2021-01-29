/*
 * Copyright (C) 2021. Nuts community
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
	"crypto"
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/pkg/errors"
	"strings"
	"time"
)

// Version defines a type for distributed document format version.
type Version int

const currentVersion = 1
const signingTimeHeader = "sigt"
const versionHeader = "ver"
const previousHeader = "prevs"
const timelineIDHeader = "tid"
const timelineVersionHeader = "tiv"

var allowedAlgos = []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512, jwa.PS256, jwa.PS384, jwa.PS512}

var errInvalidPayloadType = errors.New("payload type must be formatted as MIME type")
var errInvalidPrevs = errors.New("prevs contains an empty hash")
var unableToParseDocumentErrFmt = "unable to parse document: %w"
var documentNotValidErrFmt = "document validation failed: %w"
var missingHeaderErrFmt = "missing %s header"
var invalidHeaderErrFmt = "invalid %s header"

// UnsignedDocument holds the base properties of a document which can be signed to create a Document.
type UnsignedDocument interface {
	// PayloadType returns the MIME-formatted type of the payload. It must contain the context and specific type of the
	// payload, e.g. 'registry/endpoint'.
	PayloadType() string
	// Payload returns the hash of the payload of the document.
	Payload() hash.SHA256Hash
	// Previous returns the references of the previous documents this document points to.
	Previous() []hash.SHA256Hash
	// Version returns the version number of the distributed document format.
	Version() Version
	// TimelineID returns the timeline ID of the document.
	TimelineID() hash.SHA256Hash
	// TimelineVersion returns the timeline version of the document. If the returned version is < 1 the timeline version
	// is not set.
	TimelineVersion() int
}

// Document defines a signed distributed document as described by RFC004 - Distributed Document Format.
type Document interface {
	UnsignedDocument
	// SigningKey returns the key that was used to sign the document as JWK. If this field is not set SigningKeyID
	// must be used to resolve the signing key.
	SigningKey() jwk.Key
	// SigningKeyID returns the ID of the key that was used to sign the document. It can be used to look up the key.
	SigningKeyID() string
	// SigningTime returns the time that the document was signed.
	SigningTime() time.Time
	// Ref returns the reference to this document.
	Ref() hash.SHA256Hash
	// Data returns the byte representation of this document which can be used for transport.
	Data() []byte
	// VerifySignature verifies that the signature is correct. A function has to be supplied to look up the signing key
	// using the signing key ID, when the signing key is specified as `kid` header than than being included as `jwk`.
	// An error is returned if verification fails or something else goes wrong.
	VerifySignature(func(string) crypto.PublicKey) error
	json.Marshaler
}

// NewDocument creates a new unsigned document. Parameters payload and payloadType can't be empty, but prevs is optional.
// Prevs must not contain empty or invalid hashes.
func NewDocument(payload hash.SHA256Hash, payloadType string, prevs []hash.SHA256Hash, additionalFields ...FieldOpt) (UnsignedDocument, error) {
	if !ValidatePayloadType(payloadType) {
		return nil, errInvalidPayloadType
	}
	for _, prev := range prevs {
		if prev.Empty() {
			return nil, errInvalidPrevs
		}
	}
	result := document{
		payload:     payload,
		payloadType: payloadType,
		version:     currentVersion,
	}
	if len(prevs) > 0 {
		result.prevs = append(prevs)
	}
	for _, field := range additionalFields {
		field(&result)
	}
	return &result, nil
}

// FieldOpt defines a function for specifying fields on a document.
type FieldOpt func(target *document)

// TimelineVersionField adds the timeline version field to a document.
func TimelineVersionField(version int) FieldOpt {
	return func(target *document) {
		target.timelineVersion = version
	}
}

// ValidatePayloadType checks whether the payload type is valid according to RFC004.
func ValidatePayloadType(payloadType string) bool {
	return strings.Contains(payloadType, "/")
}

type document struct {
	prevs            []hash.SHA256Hash
	payload          hash.SHA256Hash
	payloadType      string
	signingKey       jwk.Key
	signingKeyID     string
	signingTime      time.Time
	signingAlgorithm jwa.SignatureAlgorithm
	version          Version
	timelineID       hash.SHA256Hash
	timelineVersion  int

	data []byte
	ref  hash.SHA256Hash
}

func (d document) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d.Data()))
}

func (d document) Data() []byte {
	return d.data
}

func (d document) SigningKey() jwk.Key {
	return d.signingKey
}

func (d document) SigningKeyID() string {
	return d.signingKeyID
}

func (d document) SigningTime() time.Time {
	return d.signingTime
}

func (d document) PayloadType() string {
	return d.payloadType
}

func (d document) Payload() hash.SHA256Hash {
	return d.payload
}

func (d document) Previous() []hash.SHA256Hash {
	return append(d.prevs)
}

func (d document) Ref() hash.SHA256Hash {
	return d.ref
}

func (d document) Version() Version {
	return d.version
}

func (d document) TimelineID() hash.SHA256Hash {
	return d.timelineID
}

func (d document) TimelineVersion() int {
	return d.timelineVersion
}

func (d document) VerifySignature(_ func(string) crypto.PublicKey) error {
	return errors.New("not implemented")
}

func (d *document) setData(data []byte) {
	d.data = data
	d.ref = hash.SHA256Sum(d.data)
}
