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

	"github.com/dgrijalva/jwt-go"
)

// ErrUnsupportedSigningKey is returned when an unsupported private key is used to sign. Currently only ecdsa and rsa keys are supported
var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJWT(claims map[string]interface{}, kid string) (token string, err error) {
	privateKey, err := client.Storage.GetPrivateKey(kid)

	if err != nil {
		return "", err
	}
	additionalHeaders := map[string]interface{}{
		"kid": kid,
	}

	token, err = SignJWT(privateKey, claims, additionalHeaders)
	return
}

// SignJWT signs claims with the signer and returns the compacted token. The headers param can be used to add additional headers
func SignJWT(signer crypto.Signer, claims map[string]interface{}, headers map[string]interface{}) (sig string, err error) {
	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}

	// the current version of the used JWT lib doesn't support the crypto.Signer interface. The 4.0.0 version will.
	switch signer.(type) {
	case *rsa.PrivateKey:
		token := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
		addHeaders(token, headers)
		sig, err = token.SignedString(signer.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		key := signer.(*ecdsa.PrivateKey)
		var method *jwt.SigningMethodECDSA
		if method, err = ecSigningMethod(key); err != nil {
			return
		}
		token := jwt.NewWithClaims(method, c)
		addHeaders(token, headers)
		sig, err = token.SignedString(signer.(*ecdsa.PrivateKey))
	default:
		err = errors.New("unsupported signing private key")
	}

	return
}

func addHeaders(token *jwt.Token, headers map[string]interface{}) {
	if headers == nil {
		return
	}

	for k, v := range headers {
		token.Header[k] = v
	}
}

func ecSigningMethod(key *ecdsa.PrivateKey) (method *jwt.SigningMethodECDSA, err error) {
	switch key.Params().BitSize {
	case 256:
		method = jwt.SigningMethodES256
	case 384:
		method = jwt.SigningMethodES384
	case 521:
		method = jwt.SigningMethodES512
	default:
		err = ErrUnsupportedSigningKey
	}
	return
}
