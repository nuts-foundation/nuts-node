package signature

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// Suite is an interface which defines the methods a signature suite implementation should implement.
type Suite interface {
	Sign(doc []byte, key crypto.Key) ([]byte, error)
	CanonicalizeDocument(doc map[string]interface{}) ([]byte, error)
	CalculateDigest(doc []byte) []byte
	GetType() ssi.ProofType
}

// LegacyNutsSuite is the first and wrong implementation of a JSONWebSignature.
type LegacyNutsSuite struct {
}

// Sign signs the provided doc and returns the signature bytes.
func (l LegacyNutsSuite) Sign(doc []byte, key crypto.Key) ([]byte, error) {
	sig, err := crypto.SignJWS(doc, detachedJWSHeaders(), key.Signer())
	return []byte(sig), err
}

// CanonicalizeDocument canonicalizes the document by marshalling it to json
func (l LegacyNutsSuite) CanonicalizeDocument(doc map[string]interface{}) ([]byte, error) {
	return json.Marshal(doc)
}

// CalculateDigest returns a digest for the doc by calculating the SHA256 hash.
func (l LegacyNutsSuite) CalculateDigest(doc []byte) []byte {
	return hash.SHA256Sum(doc).Slice()
}

// GetType returns the signature type
func (l LegacyNutsSuite) GetType() ssi.ProofType {
	return ssi.JsonWebSignature2020
}

// detachedJWSHeaders creates headers for JsonWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}
