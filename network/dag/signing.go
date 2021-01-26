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
	doc, ok := input.(*document)
	if !ok {
		return nil, errors.New("unsupported document")
	}
	// Preliminary sanity checks
	if signingTime.IsZero() {
		return nil, errors.New("signing time is zero")
	}
	if !doc.signingTime.IsZero() {
		return nil, errors.New("document is already signed")
	}

	var key jwk.Key
	if d.attach {
		keyAsPublicKey, err := d.resolver.GetPublicKey(d.kid)
		if err != nil {
			return nil, fmt.Errorf(errSigningDocumentFmt, err)
		}
		key, err = jwk.New(keyAsPublicKey)
		if err != nil {
			return nil, fmt.Errorf(errSigningDocumentFmt, err)
		}
	}

	prevsAsString := make([]string, len(doc.prevs))
	for i, prev := range doc.prevs {
		prevsAsString[i] = prev.String()
	}
	normalizedMoment := signingTime.UTC()
	headerMap := map[string]interface{}{
		jws.ContentTypeKey: doc.payloadType,
		jws.CriticalKey:    []string{signingTimeHeader, versionHeader, previousHeader},
		signingTimeHeader:  normalizedMoment.Unix(),
		previousHeader:     prevsAsString,
		versionHeader:      doc.Version(),
	}
	if d.attach {
		headerMap[jws.CriticalKey] = append(headerMap[jws.CriticalKey].([]string), jws.JWKKey)
		headerMap[jws.JWKKey] = key
	} else {
		headerMap[jws.CriticalKey] = append(headerMap[jws.CriticalKey].([]string), jws.KeyIDKey)
		headerMap[jws.KeyIDKey] = d.kid
	}

	if !doc.timelineID.Empty() {
		headerMap[timelineIDHeader] = doc.timelineID
		if doc.timelineVersion > 0 {
			headerMap[timelineVersionHeader] = doc.timelineVersion
		}
	}

	data, err := d.signer.SignJWS([]byte(doc.payload.String()), headerMap, d.kid)
	if err != nil {
		return nil, fmt.Errorf(errSigningDocumentFmt, err)
	}
	doc.setData([]byte(data))
	doc.signingTime = time.Unix(normalizedMoment.Unix(), 0).UTC()
	if d.attach {
		doc.signingKey = key
	} else {
		doc.signingKeyID = d.kid
	}
	return doc, nil
}
