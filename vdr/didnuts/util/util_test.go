/*
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
 *
 */

package util

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLDContextToString(t *testing.T) {
	assert.Equal(t, "https://www.w3.org/ns/did/v1", LDContextToString("https://www.w3.org/ns/did/v1"))
	assert.Equal(t, "https://www.w3.org/ns/did/v1", LDContextToString(ssi.MustParseURI("https://www.w3.org/ns/did/v1")))
	assert.Empty(t, LDContextToString(map[string]interface{}{"@base": "123"}))
}
