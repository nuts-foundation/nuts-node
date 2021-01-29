package crypto

import (
	"crypto"
	"path"
	"time"

	"github.com/sirupsen/logrus"
)

// NewTestCryptoInstance returns a new Crypto instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestCryptoInstance(testDirectory string) *Crypto {
	config := TestCryptoConfig(testDirectory)
	newInstance := &Crypto{
		Config: config,
	}
	if err := newInstance.Configure(); err != nil {
		logrus.Fatal(err)
	}
	instance = newInstance
	return newInstance
}

// TestCryptoConfig returns Config to be used in integration/unit tests.
func TestCryptoConfig(testDirectory string) Config {
	config := DefaultCryptoConfig()
	config.Fspath = path.Join(testDirectory, "crypto")
	return config
}

// StringNamingFunc can be used to give a key a simple string name
func StringNamingFunc(name string) KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return name, nil
	}
}

type StaticKeyResolver struct {
	Key crypto.PublicKey
}

func (s StaticKeyResolver) GetPublicKey(_ string, _ time.Time) (crypto.PublicKey, error) {
	return s.Key, nil
}