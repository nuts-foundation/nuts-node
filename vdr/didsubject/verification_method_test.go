/*
 * Copyright (C) 2024 Nuts community
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

package didsubject

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerificationMethodKeyType(t *testing.T) {
	tests := []struct {
		name    string
		keyType VerificationMethodKeyType
		encoded string
	}{
		{
			"all",
			VerificationMethodKeyType(31),
			"Hw",
		},
		{
			"half",
			VerificationMethodKeyType(AssertionMethodUsage | AuthenticationUsage),
			"Aw",
		},
		{
			"none",
			VerificationMethodKeyType(0),
			"",
		},
	}

	t.Run("encode", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				encoded, err := uintToString(test.keyType)

				require.NoError(t, err)
				assert.Equal(t, test.encoded, encoded)
			})
		}
	})
	t.Run("decode", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				decoded, err := stringToUint(test.encoded)

				require.NoError(t, err)
				assert.Equal(t, test.keyType, decoded)
			})
		}
	})
}

func TestVerificationMethodKeyType_Scan(t *testing.T) {
	tests := []struct {
		name    string
		keyType VerificationMethodKeyType
		encoded any
	}{
		{
			"string",
			VerificationMethodKeyType(AssertionMethodUsage | AuthenticationUsage),
			"Aw",
		},
		{
			"uint8",
			VerificationMethodKeyType(AssertionMethodUsage | AuthenticationUsage),
			[]uint8("Aw"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded VerificationMethodKeyType
			err := decoded.Scan(test.encoded)

			require.NoError(t, err)
			assert.Equal(t, test.keyType, decoded)
		})
	}
}
