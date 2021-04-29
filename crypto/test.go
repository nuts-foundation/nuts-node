package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/sirupsen/logrus"
)

// NewTestCryptoInstance returns a new Crypto instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestCryptoInstance(testDirectory string) *Crypto {
	newInstance := NewCryptoInstance()
	if err := newInstance.Configure(core.ServerConfig{Datadir: testDirectory}); err != nil {
		logrus.Fatal(err)
	}
	return newInstance
}

// StringNamingFunc can be used to give a key a simple string name
func StringNamingFunc(name string) KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return name, nil
	}
}

func ErrorNamingFunc(err error) KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return "", err
	}
}

func NewTestKey(kid string) KeySelector {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return keySelector{
		privateKey: key,
		kid:        kid,
	}
}

// TestKeySelector is a KeySelector impl for testing purposes
type TestKeySelector struct {
	PrivateKey crypto.Signer
	Kid        string
}

func (t TestKeySelector) Signer() crypto.Signer {
	return t.PrivateKey
}

func (t TestKeySelector) KID() string {
	return t.Kid
}

func (t TestKeySelector) Public() crypto.PublicKey {
	return t.PrivateKey.Public()
}
