package crypto

import (
	"crypto/ecdsa"

	ecies "github.com/ecies/go"
)

// EciesDecrypt decrypts the `cipherText` using the Elliptic Curve Integrated Encryption Scheme
func EciesDecrypt(privateKey *ecdsa.PrivateKey, cipherText []byte) ([]byte, error) {
	eciesKey := &ecies.PrivateKey{
		PublicKey: &ecies.PublicKey{
			Curve: privateKey.Curve,
			X:     privateKey.X,
			Y:     privateKey.Y,
		},
		D: privateKey.D,
	}

	return ecies.Decrypt(eciesKey, cipherText)
}

// EciesEncrypt encrypts the `plainText` using the Elliptic Curve Integrated Encryption Scheme
func (client *Crypto) EciesEncrypt(publicKey *ecdsa.PublicKey, plainText []byte) ([]byte, error) {
	eciesKey := &ecies.PublicKey{
		Curve: publicKey.Curve,
		X:     publicKey.X,
		Y:     publicKey.Y,
	}

	return ecies.Encrypt(eciesKey, plainText)
}
