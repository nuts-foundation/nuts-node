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
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// ParseTransaction parses the input as Nuts Network Transaction according to RFC004.
func ParseTransaction(input []byte) (Transaction, error) {
	message, err := jws.Parse(input)
	if err != nil {
		return nil, fmt.Errorf(unableToParseTransactionErrFmt, err)
	}
	if len(message.Signatures()) == 0 {
		return nil, transactionValidationError("JWS does not contain any signature")
	} else if len(message.Signatures()) > 1 {
		return nil, transactionValidationError("JWS contains multiple signature")
	}

	signature := message.Signatures()[0]
	headers := signature.ProtectedHeaders()

	var steps = []transactionParseStep{
		parseSigningAlgorithm,
		parsePayload,
		parseContentType,
		parseSignatureParams,
		parseSigningTime,
		parseVersion,
		parsePrevious,
		parsePAL,
		parseLamportClock,
	}

	result := &transaction{}
	result.setData(input)
	for _, step := range steps {
		if err := step(result, headers, message); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func transactionValidationError(format string, args ...interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf(transactionNotValidErrFmt, errors.New(format))
	}
	return fmt.Errorf(transactionNotValidErrFmt, fmt.Errorf(format, args...))
}

// transactionParseStep defines a function that parses a part of a JWS, building the internal representation of a transaction.
// If an error occurs during parsing or validation it should be returned.
type transactionParseStep func(transaction *transaction, headers jws.Headers, message *jws.Message) error

// parseSigningAlgorithm validates whether the signing algorithm is allowed
func parseSigningAlgorithm(_ *transaction, headers jws.Headers, _ *jws.Message) error {
	if !isAlgoAllowed(headers.Algorithm()) {
		return transactionValidationError("signing algorithm not allowed: %s", headers.Algorithm())
	}
	return nil
}

// parsePayload parses the transaction payload (contents) and sets it
func parsePayload(transaction *transaction, _ jws.Headers, message *jws.Message) error {
	payload, err := hash.ParseHex(string(message.Payload()))
	if err != nil {
		return transactionValidationError("invalid payload: %w", err)
	}
	transaction.payload = payload
	return nil
}

// parseContentType parses, validates and sets the transaction payload content type.
func parseContentType(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	contentType := headers.ContentType()
	if !ValidatePayloadType(contentType) {
		return transactionValidationError("%s", errInvalidPayloadType.Error())
	}
	transaction.payloadType = contentType
	return nil
}

// parseSignatureParams parses, validates and sets the transaction signing key (`jwk`) or key ID (`kid`).
func parseSignatureParams(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	if key, ok := headers.Get(jws.JWKKey); ok {
		jwkKey := key.(jwk.Key)
		transaction.signingKey = jwkKey
	}
	// Get the keyID from the header (not to be confused with the keyID from the embedded key)
	if kid, ok := headers.Get(jws.KeyIDKey); ok {
		transaction.signingKeyID = kid.(string)
	}
	// Check RFC004 3.1 kid and jwk constraints
	if (transaction.signingKey != nil && transaction.signingKeyID != "") || (transaction.signingKey == nil && transaction.signingKeyID == "") {
		return transactionValidationError("either `kid` or `jwk` header must be present (but not both)")
	}
	transaction.signingAlgorithm = headers.Algorithm()
	return nil
}

// parseSigningTime parses, validates and sets the transaction signing time.
func parseSigningTime(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	if timeAsInterf, ok := headers.Get(signingTimeHeader); !ok {
		return transactionValidationError(missingHeaderErrFmt, signingTimeHeader)
	} else if timeAsFloat64, ok := timeAsInterf.(float64); !ok {
		return transactionValidationError(invalidHeaderErrFmt, signingTimeHeader)
	} else {
		transaction.signingTime = time.Unix(int64(timeAsFloat64), 0).UTC()
		return nil
	}
}

// parseVersion parses, validates and sets the transaction format version.
func parseVersion(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	var version Version
	if versionAsInterf, ok := headers.Get(versionHeader); !ok {
		return transactionValidationError(missingHeaderErrFmt, versionHeader)
	} else if versionAsFloat64, ok := versionAsInterf.(float64); !ok {
		return transactionValidationError(invalidHeaderErrFmt, versionHeader)
	} else if version = Version(versionAsFloat64); !versionAllowed(version) {
		return transactionValidationError("unsupported version: %d", version)
	} else {
		transaction.version = version
		return nil
	}
}

func versionAllowed(version Version) bool {
	for _, v := range allowedVersion {
		if version == v {
			return true
		}
	}
	return false
}

// parsePrevious parses, validates and sets the transaction prevs fields.
func parsePrevious(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	if prevsAsInterf, ok := headers.Get(previousHeader); !ok {
		return transactionValidationError(missingHeaderErrFmt, previousHeader)
	} else if prevsAsSlice, ok := prevsAsInterf.([]interface{}); !ok {
		return transactionValidationError(invalidHeaderErrFmt, previousHeader)
	} else {
		for _, prevAsInterf := range prevsAsSlice {
			if prevAsString, ok := prevAsInterf.(string); !ok {
				return transactionValidationError(invalidHeaderErrFmt, previousHeader)
			} else if prev, err := hash.ParseHex(prevAsString); err != nil {
				return transactionValidationError(invalidHeaderErrFmt, previousHeader)
			} else {
				transaction.prevs = append(transaction.prevs, prev)
			}
		}
		return nil
	}
}

func parsePAL(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	rawPal, ok := headers.Get(palHeader)
	if !ok {
		return nil
	}
	palEncoded, ok := rawPal.([]interface{})
	if !ok {
		return transactionValidationError(invalidHeaderErrFmt, palHeader)
	}
	var pal [][]byte
	for _, curr := range palEncoded {
		decoded, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", curr))
		if err != nil {
			return transactionValidationError(invalidHeaderErrFmt, palHeader)
		}
		pal = append(pal, decoded)
	}
	transaction.pal = pal
	return nil
}

func parseLamportClock(transaction *transaction, headers jws.Headers, _ *jws.Message) error {
	if lcAsInterf, ok := headers.Get(lamportClockHeader); !ok {
		// won't happen since it's a critical header, but we need to check the cast anyway
		return transactionValidationError(missingHeaderErrFmt, lamportClockHeader)
	} else if lcAsFloat64, ok := lcAsInterf.(float64); !ok {
		return transactionValidationError(invalidHeaderErrFmt, lamportClockHeader)
	} else {
		transaction.lamportClock = uint32(lcAsFloat64)
		return nil
	}
}

func isAlgoAllowed(algo jwa.SignatureAlgorithm) bool {
	for _, current := range allowedAlgos {
		if algo == current {
			return true
		}
	}
	return false
}
