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
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strings"
)

func readMetadata(md metadata.MD) (transport.PeerID, did.DID, error) {
	val := func(key string, required bool) (string, error) {
		values := md.Get(key)
		if len(values) == 0 {
			if !required {
				return "", nil
			}
			return "", fmt.Errorf("peer didn't send %s header", key)
		} else if len(values) > 1 {
			return "", fmt.Errorf("peer sent multiple values for %s header", key)
		}
		return strings.TrimSpace(values[0]), nil
	}

	// Parse Peer ID
	peerIDStr, err := val(peerIDHeader, true)
	if err != nil {
		return "", did.DID{}, err
	}
	if peerIDStr == "" {
		return "", did.DID{}, fmt.Errorf("peer sent empty %s header", peerIDHeader)
	}
	// Parse Node DID
	nodeDIDStr, err := val(nodeDIDHeader, false)
	if err != nil {
		return "", did.DID{}, err
	}
	var nodeDID did.DID
	if nodeDIDStr != "" {
		parsedNodeDID, err := did.ParseDID(nodeDIDStr)
		if err != nil {
			return "", did.DID{}, fmt.Errorf("peer sent invalid node DID: %w", err)
		}
		nodeDID = *parsedNodeDID
	}
	return transport.PeerID(peerIDStr), nodeDID, nil
}

// GetStreamMethod formats the method name for the given stream.
func GetStreamMethod(serviceName string, stream grpc.StreamDesc) string {
	return fmt.Sprintf("/%s/%s", serviceName, stream.StreamName)
}
