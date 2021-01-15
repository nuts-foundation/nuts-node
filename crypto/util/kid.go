/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import (
	"crypto"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/jwk"
)

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func Fingerprint(key interface{}) (string, error) {
	k, err := jwk.New(key)
	if err != nil {
		return "", err
	}

	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// trailing '=' not allowed in kid
	return base64.RawURLEncoding.EncodeToString(tp), nil
}
