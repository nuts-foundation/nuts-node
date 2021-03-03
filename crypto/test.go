package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"time"

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

type StaticKeyResolver struct {
	Key crypto.PublicKey
}

func (s StaticKeyResolver) GetPublicKey(_ string, _ time.Time) (crypto.PublicKey, error) {
	return s.Key, nil
}

func NewTestSigner() *TestSigner {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &TestSigner{Key: key}
}

type TestSigner struct {
	Key crypto.Signer
}

func (t TestSigner) GetPublicKey(_ string, _ time.Time) (crypto.PublicKey, error) {
	return t.Key.Public(), nil
}

func (t *TestSigner) SignJWS(payload []byte, protectedHeaders map[string]interface{}, _ string) (string, error) {
	return signJWS(payload, protectedHeaders, t.Key)
}

func (t *TestSigner) SignDetachedJWS(payload []byte, _ string) (string, error) {
	return signDetachedJWS(payload, t.Key)
}
