package signature

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

type SignatureSuite interface {
	Sign(doc []byte, key crypto.Key) ([]byte, error)
	GetCanonicalDocument(doc map[string]interface{}) ([]byte, error)
	GetDigest(doc []byte) []byte
	GetType() ssi.ProofType
}

type LegacyNutsSuite struct {
}

func (l LegacyNutsSuite) Sign(doc []byte, key crypto.Key) ([]byte, error) {
	sig, err := crypto.SignJWS(doc, detachedJWSHeaders(), key.Signer())
	return []byte(sig), err
}

func (l LegacyNutsSuite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
	return json.Marshal(doc)
}

func (l LegacyNutsSuite) GetDigest(doc []byte) []byte {
	return hash.SHA256Sum(doc).Slice()
}

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
