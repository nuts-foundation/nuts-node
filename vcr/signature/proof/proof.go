package proof

import (
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

// Proof is the interface that defines a set of methods which a proof should implement.
type Proof interface {
	// Sign defines the basic signing operation on the proof.
	Sign(document map[string]interface{}, suite signature.Suite, key crypto.Key) (interface{}, error)
}
