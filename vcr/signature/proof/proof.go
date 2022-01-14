package proof

import (
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

type Proof interface {
	Sign(document map[string]interface{}, suite signature.SignatureSuite, key crypto.Key) (interface{}, error)
}
