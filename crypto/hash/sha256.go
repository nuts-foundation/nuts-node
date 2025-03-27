/*
 * Nuts node
 * Copyright (C) 2021 Nuts community

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/nuts-foundation/nuts-node/json"
)

// SHA256HashSize holds the size of a sha256 hash in bytes.
const SHA256HashSize = 32

// SHA256Hash is a SHA256 Hash over some bytes
type SHA256Hash [SHA256HashSize]byte

// MarshalText implements encoding.TextMarshaler
func (h SHA256Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// SHA256Sum creates a sha256 hash from the given bytes
func SHA256Sum(data []byte) SHA256Hash {
	return sha256.Sum256(data)
}

// String returns the SHA256Hash as a hexadecimal string.
func (h SHA256Hash) String() string {
	return hex.EncodeToString(h[:])
}

// EmptyHash returns a Hash that is empty (initialized with zeros).
func EmptyHash() SHA256Hash {
	return [SHA256HashSize]byte{}
}

// Empty tests whether the Hash is empty (all zeros).
func (h SHA256Hash) Empty() bool {
	for i := range h {
		if h[i] != 0 {
			return false
		}
	}
	return true
}

// Clone returns a copy of the Hash.
func (h SHA256Hash) Clone() SHA256Hash {
	clone := EmptyHash()
	copy(clone[:], h[:])
	return clone
}

// Slice returns the Hash as a slice. It does not copy the array.
func (h SHA256Hash) Slice() []byte {
	return h[:]
}

// Equals determines whether the given Hash is exactly the same (bytes match).
func (h SHA256Hash) Equals(other SHA256Hash) bool {
	return bytes.Equal(h[:], other[:])
}

// Compare compares this Hash to another Hash using bytes.Compare.
func (h SHA256Hash) Compare(other SHA256Hash) int {
	return bytes.Compare(h[:], other[:])
}

// Xor returns the xor of this Hash and all others. It does not change this Hash.
func (h SHA256Hash) Xor(others ...SHA256Hash) SHA256Hash {
	for n := range others {
		for i := range others[n] {
			h[i] ^= others[n][i]
		}
	}
	return h
}

// MarshalJSON marshals the hash as hex-encoded string
func (h SHA256Hash) MarshalJSON() ([]byte, error) {
	s := h.String()
	return json.Marshal(s)
}

// UnmarshalJSON converts from hex-encoded json value
func (h *SHA256Hash) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	hash, err := ParseHex(s)
	if err != nil {
		return err
	}
	copy(h[:], hash[:])

	return nil
}

// FromSlice converts a byte slice to a Hash, returning a copy.
func FromSlice(slice []byte) SHA256Hash {
	result := EmptyHash()
	copy(result[:], slice)
	return result
}

// ParseHex parses the given input string as Hash. If the input is invalid and can't be parsed as Hash, an error is returned.
func ParseHex(input string) (SHA256Hash, error) {
	if input == "" {
		return EmptyHash(), nil
	}
	data, err := hex.DecodeString(input)
	if err != nil {
		return EmptyHash(), err
	}
	if len(data) != SHA256HashSize {
		return EmptyHash(), fmt.Errorf("incorrect hash length (%d)", len(data))
	}
	result := EmptyHash()
	copy(result[0:], data)
	return result, nil
}
