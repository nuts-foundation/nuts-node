package tokenV2

import (
	"crypto/rsa"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nuts-foundation/nuts-node/http/log"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// authorizedKey is an SSH authorized key
type authorizedKey struct {
	Key     ssh.PublicKey
	Comment string
	Options []string
	JWK     jwk.Key
}

// String returns a string representation of an authorized key
func (a authorizedKey) String() string {
	encodedOptions := strings.Join(a.Options, ",")
	if encodedOptions != "" {
		encodedOptions += " "
	}
	return fmt.Sprintf("%v%v %v %v", encodedOptions, a.Key.Type(), b64.StdEncoding.EncodeToString(a.Key.Marshal()), a.Comment)
}

// jwkFromSSHKey converts a standard SSH library key to a JWX jwk.Key type
func jwkFromSSHKey(key ssh.PublicKey) (jwk.Key, error) {
	// Ensure the provided key implements the optional ssh.CryptoPublicKey interface, which
	// is able to return standard go crypto primitives. These primitives are needed to convert
	// the key into a JWX jwk key.
	var standardKey interface{}
	if cryptoPublicKey, ok := key.(ssh.CryptoPublicKey); ok {
		// Convert the ssh.PublicKey type to a go standard library crypto type (of unknown/interface{} type).
		standardKey = cryptoPublicKey.CryptoPublicKey()
	} else {
		return nil, fmt.Errorf("key (%T) does not implement the ssh.CryptoPublicKey interface and cannot be converted", key)
	}

	// Use the standard key type to create the jwk key type
	converted, err := jwk.New(standardKey)
	if err != nil {
		return nil, err
	}

	// On successful conversion also set the key ID
	if err := converted.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(key)); err != nil {
		return nil, fmt.Errorf("failed to set key id: %w", err)
	}

	return converted, nil
}

// parseAuthorizedKeys parses the contents of an SSH authorized_keys file
// into data structures and usable crypto primitives
func parseAuthorizedKeys(contents []byte) ([]authorizedKey, error) {
	// Split the contents by read
	lines := strings.Split(string(contents), "\n")

	// Loop over each line in the authorized_keys file
	var authorizedKeys []authorizedKey
	for _, line := range lines {
		// Trim leading and trailing whitespace
		line = strings.TrimLeft(line, " \t")
		line = strings.TrimRight(line, " \t")

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse this single authorized key entry
		publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("unparseable line (%v): %w", line, err)
		}

		// Ignore DSA keys, which cannot even be converted to JWX/JWK keys and need to be ignored here
		if publicKey.Type() == ssh.KeyAlgoDSA {
			log.Logger().Warnf("ignoring insecure key: %v", line)
			continue
		}

		// Ensure rest is empty, meaning the entire line was parsed
		if rest != nil {
			return nil, fmt.Errorf("line not completely parseable: %v: rest=%v", line, string(rest))
		}

		jwkPublicKey, err := jwkFromSSHKey(publicKey)
		if err != nil {
			return nil, err
		}

		// Ignore insecure keys
		if err := insecureKey(jwkPublicKey); err != nil {
			log.Logger().Warnf("ignoring insecure key: %v", line)
			continue
		}

		authorizedKeys = append(authorizedKeys, authorizedKey{
			Key:     publicKey,
			Comment: comment,
			Options: options,
			JWK:     jwkPublicKey,
		})
	}

	return authorizedKeys, nil
}

// insecureKey returns a non-nil error if a key is considered inherently insecure
func insecureKey(key jwk.Key) error {
	// Implement a blacklist of key types using the following switch statement
	switch key.KeyType() {
	// RSA keys are only secure if they are at least 2048-bits in length, though 4096-bit keys should be preferred
	case jwa.RSA:
		// Convert the JWK key to a raw RSA public key type which allows for inspection of the bit length
		var rsaKey rsa.PublicKey
		if err := key.Raw(&rsaKey); err != nil {
			return fmt.Errorf("unable to convert jwk key: %w", err)
		}

		// Accept RSA keys of at least 2048 bits in length
		if rsaKey.N.BitLen() >= 2048 {
			return nil
		}

		// Reject all other RSA keys as they are too small and therefore weak
		return errors.New("RSA keys must be at least 2048-bit")

	// Accept all other keys by default
	default:
		return nil
	}
}
