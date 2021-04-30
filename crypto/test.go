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

func NewTestKey(kid string) Key {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return keySelector{
		privateKey: key,
		kid:        kid,
	}
}

// TestKey is a Key impl for testing purposes
type TestKey struct {
	PrivateKey crypto.Signer
	Kid        string
}

func (t TestKey) Signer() crypto.Signer {
	return t.PrivateKey
}

func (t TestKey) KID() string {
	return t.Kid
}

func (t TestKey) Public() crypto.PublicKey {
	return t.PrivateKey.Public()
}
