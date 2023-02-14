package tokenV2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nuts-foundation/nuts-node/http/log"

	"github.com/lestrrat-go/jwx/jwk"
)

// minimumRSAKeySize defines the minimum length in bits of RSA keys
const minimumRSAKeySize = 2048

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

// cryptoPublicKey converts a standard SSH library key to a stdlib crypto/* key
func cryptoPublicKey(key ssh.PublicKey) (interface{}, error) {
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

	return standardKey, nil
}

// jwkFromSSHKey converts a standard SSH library key to a JWX jwk.Key type
func jwkFromSSHKey(key ssh.PublicKey) (jwk.Key, error) {
	// Convert the SSH key to a stdlib crypto/* key
	cryptoPublicKey, err := cryptoPublicKey(key)
	if err != nil {
		return nil, err
	}

	// Use the crypto/* key type to create the jwk key type
	converted, err := jwk.New(cryptoPublicKey)
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

		// Ignore insecure keys
		if secure, err := keyIsSecure(publicKey); !secure || err != nil {
			log.Logger().Warnf("ignoring insecure authorized_keys entry: %v, err=%v", line, err)
			continue
		}
                
                // Trim whitespace from the comment/username
                comment = strings.TrimSpace(comment)
                
                // Ignore keys without a comment/username
                if comment == "" {
                        log.Logger().Warnf("ignoring authorized_keys entry without comment/username: %v", line)
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

		authorizedKeys = append(authorizedKeys, authorizedKey{
			Key:     publicKey,
			Comment: comment,
			Options: options,
			JWK:     jwkPublicKey,
		})
	}

	return authorizedKeys, nil
}

// keyIsSecure returns true, nil if a key is considered secure
func keyIsSecure(key ssh.PublicKey) (bool, error) {
	// Convert the SSH key to a stdlib crypto/* key
	cryptoPublicKey, err := cryptoPublicKey(key)
	if err != nil {
		return false, err
	}

	// Implement a whitelist of accepted key types
	switch rawKey := cryptoPublicKey.(type) {
	// Accept RSA keys >= 2048-bit in length
	case *rsa.PublicKey:
		// Accept RSA keys large enough
		if bitLen := rawKey.N.BitLen(); bitLen >= minimumRSAKeySize {
			return true, nil
		}
	
		// Reject RSA keys less than 2048 bits in length as they are considered weak
		return false, errors.New("key is too weak (rsa keys must be at least 2048-bit)")

	// Accept ECDSA keys
	case *ecdsa.PublicKey:
		return true, nil

	// Accept Edwards curve keys
	case ed25519.PublicKey:
		return true, nil

	// Reject all other keys by default
	default:
		return false, fmt.Errorf("unsupported key type: %T", cryptoPublicKey)
	}
}
