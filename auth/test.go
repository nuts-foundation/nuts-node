package auth

import (
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func NewTestAuthInstance(testDirectory string) *Auth {
	return NewAuthInstance(TestConfig(), vdr.NewTestVDRInstance(testDirectory), crypto.NewTestCryptoInstance(testDirectory))
}

func TestConfig() Config {
	config := DefaultConfig()
	config.ContractValidators = []string{"dummy"}
	return config
}
