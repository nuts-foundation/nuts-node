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

package util

import (
	"errors"
)

// ErrWrongPublicKey indicates a wrong public key format
var ErrWrongPublicKey = errors.New("failed to decode PEM block containing public key, key is of the wrong type")

// ErrWrongPrivateKey indicates a wrong private key format
var ErrWrongPrivateKey = errors.New("failed to decode PEM block containing private key")

// ErrRsaPubKeyConversion indicates a public key could not be converted to an RSA public key
var ErrRsaPubKeyConversion = errors.New("unable to convert public key to RSA public key")
