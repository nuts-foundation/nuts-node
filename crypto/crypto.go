/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
 */

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
)

// Config holds the values for the crypto engine
type Config struct {
	Storage string
	Fspath  string
}

func (cc Config) getFSPath() string {
	if cc.Fspath == "" {
		return DefaultCryptoConfig().Fspath
	}

	return cc.Fspath
}

// DefaultCryptoConfig returns a Config with sane defaults
func DefaultCryptoConfig() Config {
	return Config{
		Storage: "fs",
		Fspath:  "./",
	}
}

// default implementation for Instance
type Crypto struct {
	Storage    storage.Storage
	Config     Config
	configOnce sync.Once
	configDone bool
}

type opaquePrivateKey struct {
	publicKey crypto.PublicKey
	signFn    func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

// Public returns the public key
func (k opaquePrivateKey) Public() crypto.PublicKey {
	return k.publicKey
}

// Sign signs some data with the signer
func (k opaquePrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.signFn(rand, digest, opts)
}

// Shutdown stops the certificate monitors
func (client *Crypto) Shutdown() error {
	return nil
}

// GetPrivateKey returns the specified private key. It can be used for signing, but cannot be exported.
func (client *Crypto) GetPrivateKey(kid string) (crypto.Signer, error) {
	priv, err := client.Storage.GetPrivateKey(kid)
	if err != nil {
		return nil, err
	}
	return opaquePrivateKey{publicKey: priv.Public(), signFn: priv.Sign}, nil
}

var instance *Crypto

var oneBackend sync.Once

// Instance returns the same instance of Crypto every time
func Instance() *Crypto {
	if instance != nil {
		return instance
	}
	oneBackend.Do(func() {
		instance = &Crypto{
			Config: DefaultCryptoConfig(),
		}
	})
	return instance
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure() error {
	var err error
	client.configOnce.Do(func() {
		if core.NutsConfig().Mode() != core.ServerEngineMode {
			return
		}
		if err = client.doConfigure(); err == nil {
			client.configDone = true
		}
	})
	return err
}

func (client *Crypto) doConfigure() error {
	if client.Config.Storage != "fs" && client.Config.Storage != "" {
		return errors.New("only fs backend available for now")
	}
	var err error
	if client.Storage, err = storage.NewFileSystemBackend(client.Config.getFSPath()); err != nil {
		return err
	}
	return nil
}

// GenerateKeyPair generates a new key pair. If a key pair with the same identifier already exists, it is overwritten.
func (client *Crypto) New(namingFunc KidNamingFunc) (crypto.PublicKey, error) {
	keyPair, err := generateECKeyPair()
	if err != nil {
		return nil, err
	}

	kid := namingFunc(keyPair.Public())
	if err = client.Storage.SavePrivateKey(kid, keyPair); err != nil {
		return nil, err
	}

	return jwk.PublicKeyOf(keyPair)
}

func generateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateKeyExists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) PrivateKeyExists(kid string) bool {
	return client.Storage.PrivateKeyExists(kid)
}

// GetPublicKey loads the key from storage and returns it as PEM encoded. Only supports RSA style keys
func (client *Crypto) GetPublicKey(kid string) (crypto.PublicKey, error) {
	return client.Storage.GetPublicKey(kid)
}
