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

package core

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJoinURLPaths(t *testing.T) {
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "/path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com/", "/path"))
	assert.Equal(t, "http://example.com/path/", JoinURLPaths("http://example.com/", "/path/"))
	assert.Equal(t, "http://example.com", JoinURLPaths("http://example.com"))
	assert.Equal(t, "", JoinURLPaths())
}

func Test_ParsePublicURL(t *testing.T) {
	errMissingScheme := errors.New("URL missing scheme")
	errIsIp := errors.New("hostname is IP")
	errIsReserved := errors.New("hostname is reserved")

	tests := []struct {
		input  string
		output string
		err    error
	}{
		{"https://foo.bar:5050", "foo.bar:5050", nil},
		{"http://foo.BAR", "foo.BAR", nil},
		{"grpc://fooBAR", "fooBAR", nil},
		{"fooBAR", "fooBAR", errMissingScheme},
		{"https://1.2.3.4:5555", "", errIsIp},
		{"https://[::1]:5555", "", errIsIp},
		{"https://localhost", "", errIsReserved},
		{"http://my.localhost:5555", "", errIsReserved},
		{"http://my.local", "", errIsReserved},
		{"http://LOCALhost:5555", "", errIsReserved},
		{"grpc://:5555", "", errIsReserved},
		{"grpc://example.com", "", errIsReserved},
		{"grpc://my.example.com:5555", "", errIsReserved},
	}

	for _, tc := range tests {
		addr, err := ParsePublicURL(tc.input)
		if tc.err == nil {
			// valid test cases
			require.NoError(t, err, "test case: %v", tc)
			assert.Equal(t, tc.output, addr.Host, "test case: %v", tc)
		} else {
			// invalid test cases
			assert.Empty(t, addr, "test case: %v", tc)
			assert.EqualError(t, err, tc.err.Error(), "test case: %v", tc)
		}
	}
}
