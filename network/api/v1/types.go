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

package v1

import (
	"encoding/json"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"
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
