package crypto

import (
	"path"

	"github.com/sirupsen/logrus"
)

// NewTestCryptoInstance returns a new Crypto instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestCryptoInstance(testDirectory string) *Crypto {
	config := TestCryptoConfig(testDirectory)
	newInstance := NewInstance(config)
	if err := newInstance.Configure(); err != nil {
		logrus.Fatal(err)
	}
	instance = newInstance
	return newInstance
}

// TestCryptoConfig returns CryptoConfig to be used in integration/unit tests.
func TestCryptoConfig(testDirectory string) CryptoConfig {
	config := DefaultCryptoConfig()
	config.Fspath = path.Join(testDirectory, "crypto")
	return config
}
