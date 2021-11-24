package crypto

import (
	"crypto/ecdsa"
	"errors"

	ecies "github.com/ecies/go"
)

func (client *Crypto) Decrypt(key Key, cipherText []byte) ([]byte, error) {
	ecdsaKey, ok := key.Private().(ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	privateKey := &ecies.PrivateKey{
		PublicKey: &ecies.PublicKey{
			Curve: ecdsaKey.Curve,
			X:     ecdsaKey.X,
			Y:     ecdsaKey.Y,
		},
		D: ecdsaKey.D,
	}

	return ecies.Decrypt(privateKey, cipherText)
}

func (client *Crypto) Encrypt(key Key, plainText []byte) ([]byte, error) {
	ecdsaKey, ok := key.Public().(ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type")
	}

	publicKey := &ecies.PublicKey{
		Curve: ecdsaKey.Curve,
		X:     ecdsaKey.X,
		Y:     ecdsaKey.Y,
	}

	return ecies.Encrypt(publicKey, plainText)
}
