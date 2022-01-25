package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"strings"
	"time"
)

// LegacyLDProof is a simple/wrong implementation of the LDProof specification. It uses a simple canonicalization
// algorithm and base64 encodes the payload before signing. It is here for backwards compatibility.
type LegacyLDProof struct {
	vc.JSONWebSignature2020Proof
}

// Sign signs a provided document with the provided key.
// Deprecated: this method is the initial and wrong implementation of a JSON-LD proof. There will be a new method added in the near future.
func (p LegacyLDProof) Sign(document map[string]interface{}, suite signature.Suite, key crypto.Key) (interface{}, error) {
	kid, err := ssi.ParseURI(key.KID())
	if err != nil {
		return nil, fmt.Errorf("unable to sign proof: unable parse KID as ssi.URI")
	}

	p.Type = suite.GetType()
	p.ProofPurpose = "assertionMethod"
	p.Created = time.Now()
	p.VerificationMethod = *kid

	// Don't use the suite's canonicalization method because it messes up the order of the fields:
	// (this is one of the reasons this proof is deprecated)
	// canonicalProof, err := suite.CanonicalizeDocument(p.asMap())
	canonicalProof, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return nil, err
	}

	sums := append(hash.SHA256Sum(canonicalProof).Slice(), hash.SHA256Sum(canonicalDocument).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	sig, err := suite.Sign([]byte(tbs), key)
	detachedSig := p.toDetachedSignature(string(sig))

	document["proof"] = []interface{}{
		vc.JSONWebSignature2020Proof{
			Proof: p.Proof,
			Jws:   detachedSig,
		},
	}

	return document, nil
}

// toDetachedSignature removes the middle part of the signature
func (LegacyLDProof) toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}

func (p LegacyLDProof) asMap() map[string]interface{} {
	res := map[string]interface{}{}
	b, _ := json.Marshal(p)
	json.Unmarshal(b, &res)
	return res
}
