package v1

import (
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/proto"
	"time"
)

// PeerDiagnostics defines the type for diagnostics of a peer
type PeerDiagnostics proto.Diagnostics

// UnmarshalJSON is the custom JSON unmarshaler for PeerDiagnostics
func (p *PeerDiagnostics) UnmarshalJSON(bytes []byte) error {
	result := proto.Diagnostics{}
	err := json.Unmarshal(bytes, &result)
	if err == nil {
		result.Uptime = result.Uptime * time.Second
		*p = PeerDiagnostics(result)
	}
	return err
}

// MarshalJSON is the custom JSON marshaler for PeerDiagnostics
func (p PeerDiagnostics) MarshalJSON() ([]byte, error) {
	cp := proto.Diagnostics(p)
	cp.Uptime = cp.Uptime / time.Second
	return json.Marshal(cp)
}
