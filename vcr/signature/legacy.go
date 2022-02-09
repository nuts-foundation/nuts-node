package signature

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// LegacyNutsSuite is the first and wrong implementation of a JSONWebSignature.
type LegacyNutsSuite struct {
}

func (l LegacyNutsSuite) GetProofValueKey() string {
	return "jws"
}

// Sign signs the provided doc and returns the signature bytes.
func (l LegacyNutsSuite) Sign(doc []byte, key crypto.Key) ([]byte, error) {
	sig, err := crypto.SignJWS(doc, detachedJWSHeaders(), key.Signer())
	return []byte(sig), err
}

// CanonicalizeDocument canonicalizes the document by marshalling it to json
func (l LegacyNutsSuite) CanonicalizeDocument(doc interface{}) ([]byte, error) {
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
