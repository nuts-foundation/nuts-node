/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package vcr

import (
	"github.com/nuts-foundation/go-leia/v4"
	gophonetics "gopkg.in/Regis24GmbH/go-phonetics.v2"
)

// CologneTransformer is a go-leia compatible function for generating the phonetic representation of a string.
func CologneTransformer(scalar leia.Scalar) leia.Scalar {
	switch v := scalar.(type) {
	case leia.StringScalar:
		return leia.MustParseScalar(gophonetics.NewPhoneticCode(string(v.Bytes())))
	default:
		return scalar
	}
}
