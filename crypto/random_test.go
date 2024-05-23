/*
 * Nuts node
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
 */

package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandom(t *testing.T) {
	nonce := GenerateNonce()
	decoded, _ := base64.RawURLEncoding.DecodeString(nonce)

	assert.Len(t, decoded, 32)
}
