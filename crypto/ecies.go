package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"

	ecies "github.com/nuts-foundation/crypto-ecies"
)

// EciesDecrypt decrypts the `cipherText` using the Elliptic Curve Integrated Encryption Scheme
func EciesDecrypt(privateKey *ecdsa.PrivateKey, cipherText []byte) ([]byte, error) {
	key := ecies.ImportECDSA(privateKey)

	return key.Decrypt(cipherText, nil, nil)
}

// EciesEncrypt encrypts the `plainText` using the Elliptic Curve Integrated Encryption Scheme
func EciesEncrypt(publicKey *ecdsa.PublicKey, plainText []byte) ([]byte, error) {
	key := ecies.ImportECDSAPublic(publicKey)

	return ecies.Encrypt(rand.Reader, key, plainText, nil, nil)
}
