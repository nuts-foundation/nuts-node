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
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/sirupsen/logrus"
)

// PeerID defines a peer's unique identifier.
type PeerID string

// String returns the PeerID as string.
func (p PeerID) String() string {
	return string(p)
}

// Peer holds the properties of a remote node we're connected to
type Peer struct {
	// ID holds the unique identifier of the peer
	ID PeerID `json:"id"`
	// Address holds the remote address of the node we're actually connected to
	Address string `json:"address"`
	// NodeDID holds the DID that the peer uses to identify its node on the network.
	// If Authenticated is true the NodeDID is verified.
	NodeDID did.DID `json:"nodedid"`
	// Authenticated is true when NodeDID is set and authentication is successful.
	Authenticated bool `json:"authenticated"`
	// Certificate presented by peer during TLS handshake.
	Certificate *x509.Certificate `json:"-" yaml:"-"`
}

// ToFields returns the peer as a map of fields, to be used when logging the peer details.
func (p Peer) ToFields() logrus.Fields {
	return map[string]interface{}{
		core.LogFieldPeerID:            p.ID.String(),
		core.LogFieldPeerAddr:          p.Address,
		core.LogFieldPeerNodeDID:       p.NodeDID.String(),
		core.LogFieldPeerAuthenticated: p.Authenticated,
	}
}

// Key returns a unique key for this Peer including PeerID and NodeDID.
// Usable as map index, not usable for presentation.
func (p Peer) Key() string {
	// address is included since 2 connections may exist for a peer (inbound/outbound)
	return fmt.Sprintf("%s(%s)@%s", p.ID, p.NodeDID.String(), p.Address)
}

// String returns the peer as string.
func (p Peer) String() string {
	if p.NodeDID.Empty() {
		return fmt.Sprintf("%s@%s", p.ID, p.Address)
	}
	return fmt.Sprintf("%s(%s)@%s", p.ID, p.NodeDID.String(), p.Address)
}

func (p Peer) CertificateAsPem() string {
	if p.Certificate == nil || len(p.Certificate.Raw) == 0 {
		return ""
	}
	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.Certificate.Raw,
	})
	return caPEM.String()
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
	// Certificate contains the certificate presented by the peer during the TLS handshake.
	Certificate string `json:"certificate"`
	// NodeDID of the connection.
	NodeDID string `json:"nodeDID"`
	// Address is NutsComm on outbound, or IP for inbound connections.
	Address string `json:"address"`
}

// Contact holds statistics of an outbound connector.
type Contact struct {
	// Address holds the target address the connector is connecting to.
	Address string
	// DID holds the target DID for the given Address. Is empty for bootstrap nodes
	DID did.DID
	// Attempts holds the number of times the node tried to connect to the peer.
	Attempts uint32
	// LastAttempt holds the time of the last connection attempt.
	LastAttempt *time.Time
	// NextAttempt holds the time of the next connection attempt.
	NextAttempt *time.Time
	// Error holds the errors that occurred during the connection attempts.
	Error *string
}

// NutsCommServiceType holds the DID document service type that specifies the Nuts network service address of the Nuts node.
const NutsCommServiceType = "NutsComm"

// NutsCommURL is the type which can be used to store a NutsComm endpoint in a DID Document.
// It contains the checks to validate if the endpoint is valid.
type NutsCommURL struct {
	url.URL
}

func (s *NutsCommURL) UnmarshalJSON(bytes []byte) error {
	var str string
	if err := json.Unmarshal(bytes, &str); err != nil {
		return errors.New("endpoint not a string")
	}
	endpoint, err := core.ParsePublicURL(str, false, "grpc")
	if err != nil {
		return err
	}
	*s = NutsCommURL{*endpoint}
	return nil
}
