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
	errIncompleteURL := errors.New("url must contain scheme and host")
	errIsIpAddress := errors.New("hostname is IP")
	errIsReserved := errors.New("hostname is RFC2606 reserved")
	errInvalidScheme := errors.New("scheme must be http or https or grpc")

	tests := []struct {
		allowReserved bool
		err           error
		input         string
		output        string
	}{
		{true, nil, "https://example.com", "example.com"},
		{false, nil, "https://foo.bar:5050", "foo.bar:5050"},
		{false, nil, "http://foo.BAR", "foo.BAR"},
		{false, nil, "grpc://fooBAR", "fooBAR"},
		{false, errInvalidScheme, "invalid://fooBAR", ""},
		{false, errIncompleteURL, "fooBAR", "fooBAR"},
		{false, errIncompleteURL, "https://:5555", ""},
		{false, errIsIpAddress, "https://1.2.3.4:5555", ""},
		{false, errIsIpAddress, "https://[::1]:5555", ""},
		{false, errIsReserved, "http://localhost", ""},
		{false, errIsReserved, "http://my.localhost:5555", ""},
		{false, errIsReserved, "http://my.local", ""},
		{false, errIsReserved, "grpc://LOCALhost:5555", ""},
		{false, errIsReserved, "grpc://example.com", ""},
		{false, errIsReserved, "grpc://my.example.com:5555", ""},
	}

	for _, tc := range tests {
		addr, err := ParsePublicURL(tc.input, tc.allowReserved, "http", "https", "grpc")
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
