package types

import (
	"fmt"
	"time"
)

// PeerID defines a peer's unique identifier.
type PeerID string

// String returns the PeerID as string.
func (p PeerID) String() string {
	return string(p)
}

// Peer holds the properties of a remote node we're connected to
type Peer struct {
	// ID holds the unique identificator of the peer
	ID PeerID
	// Address holds the remote address of the node we're actually connected to
	Address string
}

// String returns the peer as string.
func (p Peer) String() string {
	return fmt.Sprintf("%s@%s", p.ID, p.Address)
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