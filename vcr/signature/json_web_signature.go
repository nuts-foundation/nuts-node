package signature

import (
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/piprate/json-gold/ld"
)

// JsonWebSignature2020 Contains the correct implementation of the JsonWebSignature2020 signature suite
// It bundles the correct implementation of the canonicalize, hash and sign operations.
type JsonWebSignature2020 struct{}

// Sign signs the document as a JWS.
func (s JsonWebSignature2020) Sign(doc []byte, key crypto.Key) ([]byte, error) {
	sig, err := crypto.SignJWS(doc, detachedJWSHeaders(), key.Signer())
	return []byte(sig), err
}

// CanonicalizeDocument canonicalizes a document using the LD canonicalization algorithm.
// Can be used for both the LD proof as the document. It requires the document to have a valid context.
func (s JsonWebSignature2020) CanonicalizeDocument(doc interface{}) ([]byte, error) {
	// Fixme: move this code to another location so the loader can be cached and reused
	loader := ld.NewCachingDocumentLoader(NewEmbeddedFSDocumentLoader(assets.Assets, ld.NewDefaultDocumentLoader(nil)))
	if err := loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
		"https://schema.org":                                                 "assets/contexts/schema-org-v13.ldjson",
	}); err != nil {
		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
	}

	res, err := LDUtil{loader}.Canonicalize(doc)
	if err != nil {
		return nil, err
	}
	return []byte(res.(string)), nil
}

// CalculateDigest calculates the digest of the document. This implementation uses the SHA256 sum.
func (s JsonWebSignature2020) CalculateDigest(doc []byte) []byte {
	return hash.SHA256Sum(doc).Slice()
}

// GetType returns the signature type, 'JsonWebSignature2020'
func (s JsonWebSignature2020) GetType() ssi.ProofType {
	return ssi.JsonWebSignature2020
}

// detachedJWSHeaders returns headers for JsonWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}
