package didjwk

import (
	"fmt"
	"reflect"

        "github.com/lestrrat-go/jwx/jwk"
)

// rawPrivateKeyOf returns the private key component of a jwk.Key, or nil if one is not available (e.g. public key only JWK's). An error is returned if a public key is not contained in the JWK.
func rawPrivateKeyOf(key jwk.Key) (any, error) {
	// Get the raw key value, which is a golang crypto primitive, and possibly a private key
	var rawKey any
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// Get the public key value, which is also a jwk.Key
	publicKey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Get the raw public key, which is a golang crypto primitive, or nil
	var rawPublicKey any
	if err := publicKey.Raw(&rawPublicKey); err != nil {
		return nil, fmt.Errorf("failed to get raw public key: %w", err)
	}

	// If the raw key and the raw public key are the same then there is no private key to return
	if reflect.DeepEqual(rawKey, rawPublicKey) {
		return nil, nil
	}

	return rawKey, nil
}
