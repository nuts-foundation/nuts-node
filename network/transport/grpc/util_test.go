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

package grpc

import (
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func Test_readMetadata(t *testing.T) {
	t.Run("ok - roundtrip", func(t *testing.T) {
		peerID, nodeDID, err := readMetadata(metadata.New(map[string]string{
			peerIDHeader:  "1234",
			nodeDIDHeader: "did:nuts:test",
		}))
		require.NoError(t, err)
		assert.Equal(t, "1234", peerID.String())
		assert.Equal(t, "did:nuts:test", nodeDID.String())
	})
	t.Run("error - multiple values for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		md.Append(peerIDHeader, "1")
		md.Append(peerIDHeader, "2")
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent multiple values for peerID header")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
	t.Run("error - no values for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer didn't send peerID header")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
	t.Run("error - empty value for peer ID", func(t *testing.T) {
		md := metadata.MD{}
		md.Set(peerIDHeader, "  ")
		peerID, _, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent empty peerID header")
		assert.Empty(t, peerID.String())
	})
	t.Run("error - invalid node DID", func(t *testing.T) {
		md := metadata.MD{}
		md.Set(peerIDHeader, "1")
		md.Set(nodeDIDHeader, "invalid")
		peerID, nodeDID, err := readMetadata(md)
		assert.EqualError(t, err, "peer sent invalid node DID: invalid DID")
		assert.Empty(t, peerID.String())
		assert.Empty(t, nodeDID)
	})
}
