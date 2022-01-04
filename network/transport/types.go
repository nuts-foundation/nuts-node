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

package transport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
)

// PeerID defines a peer's unique identifier.
type PeerID string

// String returns the PeerID as string.
func (p PeerID) String() string {
	return string(p)
}

// Addr describes an address of a node on the Nuts Network.
type Addr struct {
	scheme string
	target string
}

// Empty returns whether the Addr is considered empty.
func (addr Addr) Empty() bool {
	return len(addr.scheme) == 0
}

// Scheme returns the protocol scheme of the address (e.g. "grpc").
func (addr Addr) Scheme() string {
	return addr.scheme
}

// Target returns the target of the address (e.g. "10.0.0.1:5555").
func (addr Addr) Target() string {
	return addr.target
}

// String returns the fully qualifies address, which includes the protocol scheme (e.g. "grpc").
func (addr Addr) String() string {
	if addr.Empty() {
		return ""
	}
	return addr.scheme + "://" + addr.target
}

// Address makes a new gRPC Addr given the target address.
func Address(target string) Addr {
	return Addr{
		scheme: "grpc", // we only support gRPC right now
		target: target,
	}
}

// ParseAddress parses the given input string to an Addr.
func ParseAddress(input string) (Addr, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return Addr{}, err
	}
	if parsed.Scheme != "grpc" {
		return Addr{}, errors.New("invalid URL scheme")
	}
	return Addr{scheme: parsed.Scheme, target: net.JoinHostPort(parsed.Host, parsed.Port())}, nil
}

// Peer holds the properties of a remote node we're connected to
type Peer struct {
	// ID holds the unique identificator of the peer
	ID PeerID
	// Address holds the remote address of the node we're actually connected to
	Address Addr
	// NodeDID holds the DID that the peer uses to identify its node on the network.
	// It is only set when properly authenticated.
	NodeDID did.DID
	// AcceptUnauthenticated indicates if a connection may be made with this Peer even if the NodeDID is not set.
	AcceptUnauthenticated bool
}

// String returns the peer as string.
func (p Peer) String() string {
	if p.NodeDID.Empty() {
		return fmt.Sprintf("%s@%s", p.ID, p.Address)
	}
	return fmt.Sprintf("%s(%s)@%s", p.ID, p.NodeDID.String(), p.Address)
}

// Diagnostics contains information that is shared to this node's peers on request.
type Diagnostics struct {
	// Uptime the uptime (time since the node started) in seconds.
	Uptime time.Duration `json:"uptime"`
	// Peers contains the peer IDs of the node's peers.
	Peers []PeerID `json:"peers"`
	// NumberOfTransactions contains the total number of transactions on the node's DAG.
	NumberOfTransactions uint32 `json:"transactionNum"`
	// SoftwareVersion contains an indication of the software version of the node. It's recommended to use a (Git) commit ID that uniquely resolves to a code revision, alternatively a semantic version could be used (e.g. 1.2.5).
	SoftwareVersion string `json:"softwareVersion"`
	// SoftwareID contains an indication of the vendor of the software of the node. For open source implementations it's recommended to specify URL to the public, open source repository.
	// Proprietary implementations could specify the product's or vendor's name.
	SoftwareID string `json:"softwareID"`
}

// ConnectionStats holds statistics on the connection.
type ConnectionStats struct {
	// Peer identifies the subject of these statistics.
	Peer Peer
	// ConnectAttempts holds the number of times the node tried to connect to the peer.
	ConnectAttempts uint32
}

// NutsCommServiceType holds the DID document service type that specifies the Nuts network service address of the Nuts node.
const NutsCommServiceType = "NutsComm"
