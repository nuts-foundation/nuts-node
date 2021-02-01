package dag

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto"
	"time"
)

const errSigningDocumentFmt = "error while signing document: %w"

// DocumentSigner defines functions to sign documents.
type DocumentSigner interface {
	// Sign signs the unsigned document, including the signingTime parameter as header.
	Sign(input UnsignedDocument, signingTime time.Time) (Document, error)
}

// NewAttachedJWKDocumentSigner creates a DocumentSigner that signs the document using the given key.
// The public key (identified by `kid`) is added to the signed document as `jwk` header. The public key is resolved
// using the given resolver and the `kid` parameter.
func NewAttachedJWKDocumentSigner(jwsSigner crypto.JWSSigner, kid string, keyResolver crypto.KeyResolver) DocumentSigner {
	return &documentSigner{
		signer:   jwsSigner,
		kid:      kid,
		attach:   true,
		resolver: keyResolver,
	}
}

// NewDocumentSigner creates a DocumentSigner that signs the document using the given key.
// The public key is not included in the signed document, instead the `kid` header is added which must refer to the ID
// of the used key.
func NewDocumentSigner(jwsSigner crypto.JWSSigner, kid string) DocumentSigner {
	return &documentSigner{
		signer: jwsSigner,
		kid:    kid,
		attach: false,
	}
}

type documentSigner struct {
	attach   bool
	kid      string
	signer   crypto.JWSSigner
	resolver crypto.KeyResolver
}

func (d documentSigner) Sign(input UnsignedDocument, signingTime time.Time) (Document, error) {
	// Preliminary sanity checks
	if signingTime.IsZero() {
		return nil, errors.New("signing time is zero")
	}
	if doc, ok := input.(Document); ok && !doc.SigningTime().IsZero() {
		return nil, errors.New("document is already signed")
	}

	var key jwk.Key
	if d.attach {
		keyAsPublicKey, err := d.resolver.GetPublicKey(d.kid, signingTime)
		if err != nil {
			return nil, fmt.Errorf(errSigningDocumentFmt, err)
		}
		key, err = jwk.New(keyAsPublicKey)
		if err != nil {
			return nil, fmt.Errorf(errSigningDocumentFmt, err)
		}
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

	if !input.TimelineID().Empty() {
		headerMap[timelineIDHeader] = input.TimelineID()
		if input.TimelineVersion() > 0 {
			headerMap[timelineVersionHeader] = input.TimelineVersion()
		}
	}

	data, err := d.signer.SignJWS([]byte(input.Payload().String()), headerMap, d.kid)
	if err != nil {
		return nil, fmt.Errorf(errSigningDocumentFmt, err)
	}
	signedDocument, err := ParseDocument([]byte(data))
	if err != nil {
		return nil, fmt.Errorf(errSigningDocumentFmt, err)
	}
	return signedDocument, nil
}
