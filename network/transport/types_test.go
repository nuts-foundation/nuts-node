/*
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

package transport

import (
	"errors"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
)

func Test_ParseAddress(t *testing.T) {
	errScheme := errors.New("scheme must be grpc")
	errIsIp := errors.New("hostname is IP")
	errIsReserved := errors.New("hostname is reserved")

	tests := []struct {
		input  string
		output string
		err    error
	}{
		{"grpc://foo.bar:5050", "foo.bar:5050", nil},
		{"grpc://foo.BAR", "foo.BAR", nil},
		{"grpc://fooBAR", "fooBAR", nil},
		{"foo.bar", "", errScheme},
		{"http://foo.bar", "", errScheme},
		{"grpc://1.2.3.4:5555", "", errIsIp},
		{"grpc://[::1]:5555", "", errIsIp},
		{"grpc://localhost", "", errIsReserved},
		{"grpc://my.localhost:5555", "", errIsReserved},
		{"grpc://my.local", "", errIsReserved},
		{"grpc://LOCALhost:5555", "", errIsReserved},
		{"grpc://:5555", "", errIsReserved},
		{"grpc://example.com", "", errIsReserved},
		{"grpc://my.example.com:5555", "", errIsReserved},
	}

	for _, tc := range tests {
		addr, err := parseNutsCommAddress(tc.input)
		if tc.err == nil {
			// valid test cases
			assert.Equal(t, tc.output, addr.Host, "test case: %v", tc)
			assert.NoError(t, err, "test case: %v", tc)
		} else {
			// invalid test cases
			assert.Empty(t, addr, "test case: %v", tc)
			assert.EqualError(t, err, tc.err.Error(), "test case: %v", tc)
		}
	}
}

func TestPeer_ToFields(t *testing.T) {
	peerLogFields := Peer{
		ID:            "abc",
		Address:       "def",
		NodeDID:       did.MustParseDID("did:abc:123"),
		Authenticated: true,
	}.ToFields()

	assert.Len(t, peerLogFields, 4)
	assert.Equal(t, "abc", peerLogFields[core.LogFieldPeerID])
	assert.Equal(t, "def", peerLogFields[core.LogFieldPeerAddr])
	assert.Equal(t, "did:abc:123", peerLogFields[core.LogFieldPeerNodeDID])
	assert.True(t, peerLogFields[core.LogFieldPeerAuthenticated].(bool))
}

func TestNutsCommURL_UnmarshalJSON(t *testing.T) {
	t.Run("ok - valid url", func(t *testing.T) {
		var url NutsCommURL
		err := url.UnmarshalJSON([]byte(`"grpc://foo.bar:5050"`))
		assert.NoError(t, err)
		assert.Equal(t, "foo.bar:5050", url.Host)
	})

	t.Run("error - invalid url, missing grpc", func(t *testing.T) {
		var url NutsCommURL
		err := url.UnmarshalJSON([]byte(`"foo.bar:5050"`))
		assert.EqualError(t, err, "scheme must be grpc")
	})

	t.Run("error - not a string", func(t *testing.T) {
		var url NutsCommURL
		err := url.UnmarshalJSON([]byte(`123`))
		assert.EqualError(t, err, "endpoint not a string")

	})
}
