/*
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
 *
 */

package test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
)

// GenerateRSAKey generates a 1024 bits RSA key
func GenerateRSAKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return privateKey
}

// GenerateECKey generates a P-256 EC key
func GenerateECKey() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

// StringNamingFunc can be used to give a key a simple string name
func StringNamingFunc(name string) storage.KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return name, nil
	}
}

func ErrorNamingFunc(err error) storage.KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return "", err
	}
}
