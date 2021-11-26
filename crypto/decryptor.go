package crypto

import (
	"crypto/ecdsa"
	"errors"
)

// Decrypt decrypts the `cipherText` with key `kid`
func (client *Crypto) Decrypt(kid string, cipherText []byte) ([]byte, error) {
	key, err := client.Storage.GetPrivateKey(kid)
	if err != nil {
		return nil, err
	}

	switch privateKey := key.(type) {
	case *ecdsa.PrivateKey:
		return EciesDecrypt(privateKey, cipherText)
	default:
		return nil, errors.New("unsupported decryption key")
	}
}
