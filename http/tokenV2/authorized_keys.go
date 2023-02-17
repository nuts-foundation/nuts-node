/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
package tokenV2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	b64 "encoding/base64"
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
	keyID   string
	key     ssh.PublicKey
	comment string
	options []string
	jwkSet  jwk.Set
}

// String returns a string representation of an authorized key
func (a authorizedKey) String() string {
	encodedOptions := strings.Join(a.options, ",")
	if encodedOptions != "" {
		encodedOptions += " "
	}
	return fmt.Sprintf("%v%v %v %v", encodedOptions, a.key.Type(), b64.StdEncoding.EncodeToString(a.key.Marshal()), a.comment)
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
			log.Logger().WithError(err).Warnf("Ignoring insecure authorized_keys entry: %v", line)
			continue
		}

		// Trim whitespace from the comment/username
		comment = strings.TrimSpace(comment)

		// Ignore keys without a comment/username
		if comment == "" {
			log.Logger().Warnf("Ignoring authorized_keys entry without comment/username: %v", line)
			continue
		}

		// Ensure rest is empty, meaning the entire line was parsed
		if rest != nil {
			return nil, fmt.Errorf("line not completely parseable: %v: rest=%v", line, string(rest))
		}

		// Build a JWK key set to represent this authorized public key
		jwkSet, err := buildKeySet(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to build key set: %w", err)
		}

		// Get the fingerprint of the key
		fingerprint := ssh.FingerprintSHA256(publicKey)

		// Build the struct
		authorizedKeys = append(authorizedKeys, authorizedKey{
			keyID:   fingerprint,
			key:     publicKey,
			comment: comment,
			options: options,
			jwkSet:  jwkSet,
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
		return false, fmt.Errorf("key is too weak (rsa keys must be at least %d-bit)", minimumRSAKeySize)

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

func buildKeySet(key ssh.PublicKey) (jwk.Set, error) {
	// Start with an empty key set
	keySet := jwk.NewSet()

	// Add the key with a primary (SSH) fingerprint kid
	keyPrimary, err := jwkFromSSHKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SSH key to jwk: %w", err)
	}
	keySet.Add(keyPrimary)

	// Create an alternate representaiton of the jwk, which will have a different kid
	keyAlt, err := jwkFromSSHKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SSH key to jwk: %w", err)
	}

	// Remove any existing key ID
	if err := keyAlt.Remove(jwk.KeyIDKey); err != nil {
		return nil, fmt.Errorf("failed to remove kid: %w", err)
	}

	// Rebuild the key ID using the JWK SHA256 fingerprint
	if err := jwk.AssignKeyID(keyAlt, jwk.WithThumbprintHash(crypto.SHA256)); err != nil {
		return nil, fmt.Errorf("failed to fingerprint key: %w", err)
	}

	// Add the alternate jwk to the key set
	keySet.Add(keyAlt)

	// Return the key set which contains the key twice: once with SSH fingerprint and once with JWK fingerprint
	return keySet, nil
}
