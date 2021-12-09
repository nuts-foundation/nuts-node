package crypto

import (
	"crypto/ecdsa"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCrypto_Decrypt(t *testing.T) {
	client := createCrypto(t)
	kid := "kid"
	key, _ := client.New(StringNamingFunc(kid))
	pubKey := key.Public().(*ecdsa.PublicKey)

	cipherText, err := EciesEncrypt(pubKey, []byte("hello!"))
	assert.NoError(t, err)

	plainText, err := client.Decrypt("kid", cipherText)
	assert.NoError(t, err)

	assert.Equal(t, "hello!", string(plainText))
}
