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
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strings"
	"time"
)

func readMetadata(md metadata.MD) (transport.PeerID, error) {
	values := md.Get(peerIDHeader)
	if len(values) == 0 {
		return "", fmt.Errorf("peer didn't send %s header", peerIDHeader)
	} else if len(values) > 1 {
		return "", fmt.Errorf("peer sent multiple values for %s header", peerIDHeader)
	}
	peerID := transport.PeerID(strings.TrimSpace(values[0]))
	if peerID == "" {
		return "", fmt.Errorf("peer sent empty %s header", peerIDHeader)
	}
	return peerID, nil
}

func constructMetadata(peerID transport.PeerID) metadata.MD {
	return metadata.New(map[string]string{
		peerIDHeader:          string(peerID),
		protocolVersionHeader: protocolVersionV1, // required for backwards compatibility with v1
	})
}

// GetStreamMethod formats the method name for the given stream.
func GetStreamMethod(serviceName string, stream grpc.StreamDesc) string {
	return fmt.Sprintf("/%s/%s", serviceName, stream.StreamName)
}

func sleepWithCancel(ctx context.Context, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(duration):
	}
}
