package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEciesEncrypt(t *testing.T) {
	key, err := generateECKeyPair()
	assert.NoError(t, err)

	cipherText1, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	cipherText2, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	assert.NotEqual(t, cipherText1, cipherText2)
}

func TestEciesDecrypt(t *testing.T) {
	key, err := generateECKeyPair()
	assert.NoError(t, err)

	cipherText, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	plainText, err := EciesDecrypt(key, cipherText)
	assert.NoError(t, err)

	assert.Equal(t, []byte("hello world"), plainText)
}
