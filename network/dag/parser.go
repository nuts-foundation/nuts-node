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
	"bytes"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// ParseDocument parses the input as Nuts Network Document according to RFC004.
func ParseDocument(input []byte) (Document, error) {
	message, err := jws.Parse(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf(unableToParseDocumentErrFmt, err)
	}
	if len(message.Signatures()) == 0 {
		return nil, documentValidationError("JWS does not contain any signature")
	} else if len(message.Signatures()) > 1 {
		return nil, documentValidationError("JWS contains multiple signature")
	}

	signature := message.Signatures()[0]
	headers := signature.ProtectedHeaders()

	var steps = []documentParseStep{
		parseSigningAlgorithm,
		parsePayload,
		parseContentType,
		parseSignatureParams,
		parseSigningTime,
		parseVersion,
		parsePrevious,
		parseTimelineID,
		parseTimelineVersion,
	}

	result := &document{}
	result.setData(input)
	for _, step := range steps {
		if err := step(result, headers, message); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func documentValidationError(format string, args ...interface{}) error {
	return fmt.Errorf(documentNotValidErrFmt, fmt.Errorf(format, args...))
}

// documentParseStep defines a function that parses a part of a JWS, building the internal representation of a document.
// If an error occurs during parsing or validation it should be returned.
type documentParseStep func(document *document, headers jws.Headers, message *jws.Message) error

// parseSigningAlgorithm validates whether the signing algorithm is allowed
func parseSigningAlgorithm(_ *document, headers jws.Headers, _ *jws.Message) error {
	if !isAlgoAllowed(headers.Algorithm()) {
		return documentValidationError("signing algorithm not allowed: %s", headers.Algorithm())
	}
	return nil
}

// parsePayload parses the document payload (contents) and sets it
func parsePayload(document *document, _ jws.Headers, message *jws.Message) error {
	payload, err := hash.ParseHex(string(message.Payload()))
	if err != nil {
		return documentValidationError("invalid payload: %w", err)
	}
	document.payload = payload
	return nil
}

// parseContentType parses, validates and sets the document payload content type.
func parseContentType(document *document, headers jws.Headers, _ *jws.Message) error {
	contentType := headers.ContentType()
	if !ValidatePayloadType(contentType) {
		return documentValidationError(errInvalidPayloadType.Error())
	}
	document.payloadType = contentType
	return nil
}

// parseSignatureParams parses, validates and sets the document signing key (`jwk`) or key ID (`kid`).
func parseSignatureParams(document *document, headers jws.Headers, _ *jws.Message) error {
	if key, ok := headers.Get(jws.JWKKey); ok {
		jwkKey := key.(jwk.Key)
		// Check RFC004 3.1 kid constraints
		// A embedded jwk must have a keyID
		if jwkKey.KeyID() == "" {
			return documentValidationError("when present, the `jwk` must contain a valid `kid`")
		}
		document.signingKey = jwkKey
	}
	// Get the keyID from the header (not to be confused with the keyID from the embedded key)
	if kid, ok := headers.Get(jws.KeyIDKey); ok {
		document.signingKeyID = kid.(string)
	}
	// Check RFC004 3.1 kid and jwk constraints
	if (document.signingKey != nil && document.signingKeyID != "") || (document.signingKey == nil && document.signingKeyID == "") {
		return documentValidationError("either `kid` or `jwk` header must be present (but not both)")
	}
	document.signingAlgorithm = headers.Algorithm()
	return nil
}

// parseSigningTime parses, validates and sets the document signing time.
func parseSigningTime(document *document, headers jws.Headers, _ *jws.Message) error {
	if timeAsInterf, ok := headers.Get(signingTimeHeader); !ok {
		return documentValidationError(missingHeaderErrFmt, signingTimeHeader)
	} else if timeAsFloat64, ok := timeAsInterf.(float64); !ok {
		return documentValidationError(invalidHeaderErrFmt, signingTimeHeader)
	} else {
		document.signingTime = time.Unix(int64(timeAsFloat64), 0).UTC()
		return nil
	}
}

// parseVersion parses, validates and sets the document format version.
func parseVersion(document *document, headers jws.Headers, _ *jws.Message) error {
	var version Version
	if versionAsInterf, ok := headers.Get(versionHeader); !ok {
		return documentValidationError(missingHeaderErrFmt, versionHeader)
	} else if versionAsFloat64, ok := versionAsInterf.(float64); !ok {
		return documentValidationError(invalidHeaderErrFmt, versionHeader)
	} else if version = Version(versionAsFloat64); version != currentVersion {
		return documentValidationError("unsupported version: %d", version)
	} else {
		document.version = version
		return nil
	}
}

// parsePrevious parses, validates and sets the document prevs fields.
func parsePrevious(document *document, headers jws.Headers, _ *jws.Message) error {
	if prevsAsInterf, ok := headers.Get(previousHeader); !ok {
		return documentValidationError(missingHeaderErrFmt, previousHeader)
	} else if prevsAsSlice, ok := prevsAsInterf.([]interface{}); !ok {
		return documentValidationError(invalidHeaderErrFmt, previousHeader)
	} else {
		for _, prevAsInterf := range prevsAsSlice {
			if prevAsString, ok := prevAsInterf.(string); !ok {
				return documentValidationError(invalidHeaderErrFmt, previousHeader)
			} else if prev, err := hash.ParseHex(prevAsString); err != nil {
				return documentValidationError(invalidHeaderErrFmt, previousHeader)
			} else {
				document.prevs = append(document.prevs, prev)
			}
		}
		return nil
	}
}

// parseTimelineID parses, validates and sets the document timeline ID field.
func parseTimelineID(document *document, headers jws.Headers, _ *jws.Message) error {
	if tidAsInterf, _ := headers.Get(timelineIDHeader); tidAsInterf != nil {
		if tidAsString, ok := tidAsInterf.(string); !ok {
			return documentValidationError(invalidHeaderErrFmt, timelineIDHeader)
		} else if timelineID, err := hash.ParseHex(tidAsString); err != nil {
			return documentValidationError(invalidHeaderErrFmt+": %w", timelineIDHeader, err)
		} else {
			document.timelineID = timelineID
		}
	}
	return nil
}

// parseTimelineVersion parses, validates and sets the document timeline version field. Timeline ID must be present when
// timeline version is present.
func parseTimelineVersion(document *document, headers jws.Headers, _ *jws.Message) error {
	tivAsInterf, _ := headers.Get(timelineVersionHeader)
	if tivAsInterf == nil {
		return nil
	}
	if tiv, ok := tivAsInterf.(float64); !ok {
		return documentValidationError(invalidHeaderErrFmt, timelineVersionHeader)
	} else if tiv < 0 {
		return documentValidationError(invalidHeaderErrFmt, timelineVersionHeader)
	} else if document.timelineID.Empty() {
		return documentValidationError("%s specified without %s header", timelineVersionHeader, timelineIDHeader)
	} else if tiv != float64(int(tiv)) {
		return documentValidationError(invalidHeaderErrFmt, timelineVersionHeader)
	} else {
		document.timelineVersion = int(tiv)
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
