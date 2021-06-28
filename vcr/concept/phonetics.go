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
 *
 */

package concept

import (
	gophonetics "github.com/Regis24GmbH/go-phonetics"
	"github.com/nuts-foundation/go-leia"
)

// CologneTransformer is a go-leia compatible function for generating the phonetic representation of a string.
func CologneTransformer(text interface{}) interface{} {
	switch v := text.(type) {
	case string:
		return gophonetics.NewPhoneticCode(v)
	case leia.Key:
		return gophonetics.NewPhoneticCode(v.String())
	default:
		return text
	}
}
