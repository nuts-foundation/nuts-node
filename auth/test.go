package auth

import (
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/store"
)

func NewTestAuthInstance(testDirectory string) *Auth {
	return NewAuthInstance(
		TestConfig(),
		store.NewMemoryStore(),
		vcr.NewTestVCRInstance(testDirectory),
		crypto.NewTestCryptoInstance(testDirectory),
		nil,
	)
}

func TestConfig() Config {
	config := DefaultConfig()
	config.ContractValidators = []string{"dummy"}
	return config
}
