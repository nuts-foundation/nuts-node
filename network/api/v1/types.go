package v1

import (
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"time"
)

// PeerDiagnostics defines the type for diagnostics of a peer
type PeerDiagnostics types.Diagnostics

// UnmarshalJSON is the custom JSON unmarshaler for PeerDiagnostics
func (p *PeerDiagnostics) UnmarshalJSON(bytes []byte) error {
	result := types.Diagnostics{}
	err := json.Unmarshal(bytes, &result)
	if err == nil {
		result.Uptime = result.Uptime * time.Second
		*p = PeerDiagnostics(result)
	}
	return err
}

// MarshalJSON is the custom JSON marshaler for PeerDiagnostics
func (p PeerDiagnostics) MarshalJSON() ([]byte, error) {
	cp := types.Diagnostics(p)
	cp.Uptime = cp.Uptime / time.Second
	return json.Marshal(cp)
}
