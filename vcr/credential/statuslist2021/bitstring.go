/*
 * Copyright (C) 2023 Nuts community
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

package statuslist2021

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
)

var ErrIndexNotInBitstring = errors.New("index not in status list")

const defaultBitstringLengthInBytes = 16 * 1024 // *8 = herd privacy of 16kB or 131072 bit
const MaxBitstringIndex = defaultBitstringLengthInBytes*8 - 1

// Bitstring is not thread-safe
type Bitstring []byte

// NewBitstring creates a new Bitstring with 16kB entries initialized to 0.
func NewBitstring() *Bitstring {
	bs := Bitstring(make([]byte, defaultBitstringLengthInBytes))
	return &bs
}

// Bit returns the value of the Bitstring at statusListIndex, or (false, error) if the requested index is out of bounds.
func (bs *Bitstring) Bit(statusListIndex int) (bool, error) {
	q, r := statusListIndex/8, byte(statusListIndex%8)
	if statusListIndex < 0 || q >= len(*bs) {
		return false, ErrIndexNotInBitstring
	}
	return isSet((*bs)[q], r), nil
}

// SetBit set the value of the bit at statusListIndex to 1, or returns an error when the index is out of bounds.
func (bs *Bitstring) SetBit(statusListIndex int, value bool) error {
	q, r := statusListIndex/8, byte(statusListIndex%8)
	if statusListIndex < 0 || q >= len(*bs) {
		return ErrIndexNotInBitstring
	}
	// flip value if needed
	if isSet((*bs)[q], r) != value {
		(*bs)[q] ^= 1 << (7 - r)
	}
	return nil
}

// isSet returns true if the r-th bit in b is 1. r MUST be in range [0, 7].
func isSet(b, r byte) bool {
	return b>>(7-r)&1 == 1
}

// Compress a StatusList2021 bitstring. The input is gzip compressed followed by base64 encoding.
func Compress(bitstring []byte) (string, error) {
	// gzip compression
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(bitstring)
	if err != nil {
		return "", err
	}
	err = gz.Close()
	if err != nil {
		return "", err
	}

	// encode to base64 string.
	// Bitstring Status List spec clarified this to be multibase base64URL encoding without padding. StatusList2021 spec is not multibase.
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// Expand a compressed StatusList2021 bitstring. It first applies base64 decoding followed by gzip decompression.
func Expand(encodedList string) (Bitstring, error) {
	// base64 decode
	// Bitstring Status List spec clarified this to be multibase base64URL encoding without padding. StatusList2021 spec is not multibase.
	enc := base64.RawURLEncoding
	if len(encodedList)%4 == 0 {
		// if encoding is a multiple of 4 it may or may not be padded. URLEncoding can handle both.
		enc = base64.URLEncoding
	}

	compressed, err := enc.DecodeString(encodedList)
	if err != nil {
		return nil, err
	}

	// gzip decompression
	gzr, err := gzip.NewReader(bytes.NewBuffer(compressed))
	if err != nil {
		return nil, err
	}
	var expanded bytes.Buffer
	_, err = expanded.ReadFrom(gzr)
	if err != nil {
		return nil, err
	}

	return expanded.Bytes(), nil
}
