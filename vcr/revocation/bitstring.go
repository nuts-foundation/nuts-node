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

package revocation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
)

var ErrIndexNotInBitstring = errors.New("index not in status list")

const defaultBitstringLengthInBytes = 16 * 1024 // *8 = herd privacy of 16kB or 131072 bit
const maxBitstringIndex = defaultBitstringLengthInBytes*8 - 1

// bitstring is not thread-safe
type bitstring []byte

// newBitstring creates a new bitstring with 16kB entries initialized to 0.
func newBitstring() *bitstring {
	bs := bitstring(make([]byte, defaultBitstringLengthInBytes))
	return &bs
}

// bit returns the value of the bitstring at statusListIndex, or (false, error) if the requested index is out of bounds.
func (bs *bitstring) bit(statusListIndex int) (bool, error) {
	q, r := statusListIndex/8, byte(statusListIndex%8)
	if statusListIndex < 0 || q >= len(*bs) {
		return false, ErrIndexNotInBitstring
	}
	return isSet((*bs)[q], r), nil
}

// setBit set the value of the bit at statusListIndex to 1, or returns an error when the index is out of bounds.
func (bs *bitstring) setBit(statusListIndex int, value bool) error {
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

// compress a StatusList2021 bitstring. The input is gzip compressed followed by base64 encoding.
func compress(bitstring []byte) (string, error) {
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
	// bitstring Status List spec clarified this to be multibase base64URL encoding without padding. StatusList2021 spec is not multibase.
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// expand a compressed StatusList2021 bitstring. It first applies base64 decoding followed by gzip decompression.
func expand(encodedList string) (bitstring, error) {
	// base64 decode
	// bitstring Status List spec clarified this to be multibase base64URL encoding without padding. StatusList2021 spec is not multibase.
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
