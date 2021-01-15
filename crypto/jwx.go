/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"crypto/rsa"
	"errors"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// ErrUnsupportedSigningKey is returned when an unsupported private key is used to sign. Currently only ecdsa and rsa keys are supported
var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJWT(claims map[string]interface{}, kid string) (token string, err error) {
	privateKey, err := client.Storage.GetPrivateKey(kid)

	if err != nil {
		return "", err
	}
	key, err := jwkKey(privateKey)
	if err != nil {
		return "", err
	}

	if err = jwk.AssignKeyID(key); err != nil {
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
		t.Set(k, v)
	}
	hdr := convertHeaders(headers)

	sig, err = jwt.Sign(t, jwa.SignatureAlgorithm(key.Algorithm()), key, jws.WithHeaders(hdr))
	token = string(sig)

	return
}

// JWTAlg parses a JWT, does not validate it and returns the 'kid' and 'alg' headers
func JWTKidAlg(tokenString string) (string, jwa.SignatureAlgorithm, error) {
	j, err := jws.ParseString(tokenString)
	if err != nil {
		return "", "", err
	}

	if len(j.Signatures()) != 1 {
		return "", "", errors.New("incorrect amount of signatures in JWT")
	}

	sig := j.Signatures()[0]
	hdrs := sig.ProtectedHeaders()
	return hdrs.KeyID(), hdrs.Algorithm(), nil
}

// PublicKeyFunc defines a function that resolves a public key based on a kid
type PublicKeyFunc func(kid string) (crypto.PublicKey, error)

// ParseJWT parses a token, validates and verifies it.
func ParseJWT(tokenString string, f PublicKeyFunc) (jwt.Token, error){
	kid, alg, err := JWTKidAlg(tokenString)
	if err != nil {
		return nil, err
	}

	key, err := f(kid)
	if err != nil {
		return nil, err
	}

	return jwt.ParseString(tokenString, jwt.WithVerify(alg, key), jwt.WithValidate(true))
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
