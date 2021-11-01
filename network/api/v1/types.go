package v1

import (
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"time"
)

// PeerDiagnostics defines the type for diagnostics of a peer
type PeerDiagnostics transport.Diagnostics

// UnmarshalJSON is the custom JSON unmarshaler for PeerDiagnostics
func (p *PeerDiagnostics) UnmarshalJSON(bytes []byte) error {
	result := transport.Diagnostics{}
	err := json.Unmarshal(bytes, &result)
	if err == nil {
		result.Uptime = result.Uptime * time.Second
		*p = PeerDiagnostics(result)
	}
	return err
}

// MarshalJSON is the custom JSON marshaler for PeerDiagnostics
func (p PeerDiagnostics) MarshalJSON() ([]byte, error) {
	cp := transport.Diagnostics(p)
	cp.Uptime = cp.Uptime / time.Second
	return json.Marshal(cp)
}
