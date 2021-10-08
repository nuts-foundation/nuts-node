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

package p2p

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func Test_normalizeAddress(t *testing.T) {
	t.Run("invalid address", func(t *testing.T) {
		assert.Equal(t, "not a valid address", normalizeAddress("not a valid address"))
	})
	t.Run("address is already normalized (IP)", func(t *testing.T) {
		assert.Equal(t, "1.2.3.4:1234", normalizeAddress("1.2.3.4:1234"))
	})
	t.Run("address is already normalized (hostname)", func(t *testing.T) {
		assert.Equal(t, "foobar:1234", normalizeAddress("foobar:1234"))
	})
	t.Run("address is localhost (hostname)", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1:1234", normalizeAddress("localhost:1234"))
	})
	t.Run("address is localhost (IP)", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1:1234", normalizeAddress("127.0.0.1:1234"))
	})
}

func Test_peerIDFromMetadata(t *testing.T) {
	t.Run("ok - roundtrip", func(t *testing.T) {
		md := constructMetadata("1234")
		peerID, err := peerIDFromMetadata(md)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "1234", peerID.String())
	})
	t.Run("error - multiple values", func(t *testing.T) {
		md := metadata.MD{}
		md.Append(peerIDHeader, "1")
		md.Append(peerIDHeader, "2")
		peerID, err := peerIDFromMetadata(md)
		assert.EqualError(t, err, "peer sent multiple values for peerID header")
		assert.Empty(t, peerID.String())
	})
	t.Run("error - no values", func(t *testing.T) {
		md := metadata.MD{}
		peerID, err := peerIDFromMetadata(md)
		assert.EqualError(t, err, "peer didn't send peerID header")
		assert.Empty(t, peerID.String())
	})
	t.Run("error - empty value", func(t *testing.T) {
		md := metadata.MD{}
		md.Set(peerIDHeader, "  ")
		peerID, err := peerIDFromMetadata(md)
		assert.EqualError(t, err, "peer sent empty peerID header")
		assert.Empty(t, peerID.String())
	})
}

func Test_constructMetadata(t *testing.T) {
	t.Run("set default protocol version", func(t *testing.T) {
		md := constructMetadata("1234")

		v := md.Get(protocolHeader)

		assert.Len(t, v, 1)
		assert.Equal(t, protocolVersionV1, v[0])
	})
}

func Test_protocolVersionFromMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		md := metadata.MD{}
		md.Append(protocolHeader, "v2")

		v, err := protocolVersionFromMetadata(md)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "v2", v)
	})

	t.Run("v1 for missing header", func(t *testing.T) {
		md := metadata.MD{}

		v, err := protocolVersionFromMetadata(md)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, protocolVersionV1, v)
	})

	t.Run("error - too many values", func(t *testing.T) {
		md := metadata.MD{}
		md.Append(protocolHeader, "v1")
		md.Append(protocolHeader, "v2")

		v, err := protocolVersionFromMetadata(md)

		assert.EqualError(t, err, "peer sent multiple values for version header")
		assert.Empty(t, v)
	})
}
