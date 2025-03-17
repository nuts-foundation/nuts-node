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

package services

import (
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNutsAccessToken_FromMap(t *testing.T) {
	expected := NutsAccessToken{Service: "Foobar"}
	asJSON, _ := json.Marshal(&expected)
	var asMap map[string]interface{}
	err := json.Unmarshal(asJSON, &asMap)
	require.NoError(t, err)
	var actual NutsAccessToken
	err = actual.FromMap(asMap)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
