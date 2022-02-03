/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/shengdoushi/base58"
)

// ErrUnsupportedSigningKey is returned when an unsupported private key is used to sign. Currently only ecdsa and rsa keys are supported
var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

var supportedAlgorithms = []jwa.SignatureAlgorithm{jwa.PS256, jwa.PS384, jwa.PS512, jwa.ES256, jwa.ES384, jwa.ES512}

func isAlgorithmSupported(alg jwa.SignatureAlgorithm) bool {
	for _, curr := range supportedAlgorithms {
		if curr == alg {
			return true
		}
	}
	return false
}

// SignJWT creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJWT(claims map[string]interface{}, kid string) (token string, err error) {
	privateKey, err := client.Storage.GetPrivateKey(kid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrKeyNotFound
		}
		return "", err
	}
	key, err := jwkKey(privateKey)
	if err != nil {
		return "", err
	}

	if err = key.Set(jwk.KeyIDKey, kid); err != nil {
		return "", err
	}

	token, err = SignJWT(key, claims, nil)
	return
}

func jwkKey(signer crypto.Signer) (key jwk.Key, err error) {
	key, err = jwk.New(signer)
	if err != nil {
		return nil, err
	}

	switch signer.(type) {
	case *rsa.PrivateKey:
		key.Set(jwk.AlgorithmKey, jwa.PS256)
	case *ecdsa.PrivateKey:
		ecKey := signer.(*ecdsa.PrivateKey)
		var alg jwa.SignatureAlgorithm
		alg, err = ecAlg(ecKey)
		key.Set(jwk.AlgorithmKey, alg)
	default:
		err = errors.New("unsupported signing private key")
	}
	return
}

// SignJWT signs claims with the signer and returns the compacted token. The headers param can be used to add additional headers
func SignJWT(key jwk.Key, claims map[string]interface{}, headers map[string]interface{}) (token string, err error) {
	var sig []byte
	t := jwt.New()

	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return "", err
		}
	}
	hdr := convertHeaders(headers)

	sig, err = jwt.Sign(t, jwa.SignatureAlgorithm(key.Algorithm()), key, jwt.WithHeaders(hdr))
	token = string(sig)

	return
}

// JWTKidAlg parses a JWT, does not validate it and returns the 'kid' and 'alg' headers
func JWTKidAlg(tokenString string) (string, jwa.SignatureAlgorithm, error) {
	j, err := jws.ParseString(tokenString)
	if err != nil {
		return "", "", err
	}

	if len(j.Signatures()) != 1 {
		return "", "", errors.New("incorrect number of signatures in JWT")
	}

	sig := j.Signatures()[0]
	hdrs := sig.ProtectedHeaders()
	return hdrs.KeyID(), hdrs.Algorithm(), nil
}

// PublicKeyFunc defines a function that resolves a public key based on a kid
type PublicKeyFunc func(kid string) (crypto.PublicKey, error)

// ParseJWT parses a token, validates and verifies it.
func ParseJWT(tokenString string, f PublicKeyFunc, options ...jwt.ParseOption) (jwt.Token, error) {
	kid, alg, err := JWTKidAlg(tokenString)
	if err != nil {
		return nil, err
	}

	key, err := f(kid)
	if err != nil {
		return nil, err
	}

	if !isAlgorithmSupported(alg) {
		return nil, fmt.Errorf("token signing algorithm is not supported: %s", alg)
	}

	options = append(options, jwt.WithVerify(alg, key))
	options = append(options, jwt.WithValidate(true))

	return jwt.ParseString(tokenString, options...)
}

func SignJWS(payload []byte, protectedHeaders map[string]interface{}, privateKey crypto.Signer) (string, error) {
	headers := jws.NewHeaders()
	for key, value := range protectedHeaders {
		if err := headers.Set(key, value); err != nil {
			return "", fmt.Errorf("unable to set header %s: %w", key, err)
		}
	}
	privateKeyAsJWK, err := jwkKey(privateKey)
	if err != nil {
		return "", err
	}
	// The JWX library is fine with creating a JWK for a private key (including the private exponents), so
	// we want to make sure the `jwk` header (if present) does not (accidentally) contain a private key.
	// That would lead to the node leaking its private key material in the resulting JWS which would be very, very bad.
	if headers.JWK() != nil {
		var jwkAsPrivateKey crypto.Signer
		if err := headers.JWK().Raw(&jwkAsPrivateKey); err == nil {
			// `err != nil` is good in this case, because that means the key is not assignable to crypto.Signer,
			// which is the interface implemented by all private key types.
			return "", errors.New("refusing to sign JWS with private key in JWK header")
		}
	}
	algo := jwa.SignatureAlgorithm(privateKeyAsJWK.Algorithm())

	// We assume here that if the b64 header is set to false, we create a JWS with a detached payload.
	var (
		data []byte
	)
	payloadIsB64 := true
	if b64, ok := headers.Get("b64"); ok {
		if payloadIsB64, ok = b64.(bool); !ok {
			return "", errors.New("unable to read b64 JWS header as bool")
		}
	}

	if payloadIsB64 {
		// Sign normal JWS
		data, err = jws.Sign(payload, algo, privateKey, jws.WithHeaders(headers))
	} else {
		// Sign JWS with detached payload
		data, err = jws.Sign(nil, algo, privateKey, jws.WithHeaders(headers), jws.WithDetachedPayload(payload))
	}
	if err != nil {
		return "", fmt.Errorf("unable to sign JWS %w", err)
	}
	return string(data), nil
}

func convertHeaders(headers map[string]interface{}) (hdr jws.Headers) {
	hdr = jws.NewHeaders()

	if headers != nil {
		for k, v := range headers {
			hdr.Set(k, v)
		}
	}
	return
}

func ecAlg(key *ecdsa.PrivateKey) (alg jwa.SignatureAlgorithm, err error) {
	alg, err = ecAlgUsingPublicKey(key.PublicKey)
	return
}

func ecAlgUsingPublicKey(key ecdsa.PublicKey) (alg jwa.SignatureAlgorithm, err error) {
	switch key.Params().BitSize {
	case 256:
		alg = jwa.ES256
	case 384:
		alg = jwa.ES384
	case 521:
		alg = jwa.ES512
	default:
		err = ErrUnsupportedSigningKey
	}
	return
}

// SignatureAlgorithm determines the jwa.SigningAlgorithm for ec/rsa/ed25519 keys.
func SignatureAlgorithm(key crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	if key == nil {
		return "", errors.New("no key provided")
	}

	var ptr interface{}
	switch v := key.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case rsa.PublicKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	case ecdsa.PublicKey:
		ptr = &v
	default:
		ptr = v
	}

	switch ptr.(type) {
	case *rsa.PrivateKey:
		return jwa.PS256, nil
	case *rsa.PublicKey:
		return jwa.PS256, nil
	case *ecdsa.PrivateKey:
		sk := ptr.(*ecdsa.PrivateKey)
		return ecAlgUsingPublicKey(sk.PublicKey)
	case *ecdsa.PublicKey:
		pk := ptr.(*ecdsa.PublicKey)
		return ecAlgUsingPublicKey(*pk)
	case ed25519.PrivateKey:
		return jwa.EdDSA, nil
	case ed25519.PublicKey:
		return jwa.EdDSA, nil
	default:
		return "", fmt.Errorf(`invalid key type '%T' for jwk.New`, key)
	}
}

// Thumbprint generates a Nuts compatible thumbprint: Base58(SHA256(rfc7638-json))
func Thumbprint(key jwk.Key) (string, error) {
	pkHash, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base58.Encode(pkHash[:], base58.BitcoinAlphabet), nil
}
