package statuslist2021

// TODO: copyright

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
)

var ErrIndexNotInBitstring = errors.New("index not in status list")

var defaultBitstringLengthInBytes = 16 * 1024 // *8 = herd privacy of 16kB or 131072 bit

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

	// encode to base64 string
	// the examples contain '-' from which I took that is uses URLEncoding over StdEncoding
	return base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

// Expand a compressed StatusList2021 bitstring. It first applies base64 decoding followed by gzip decompression.
func Expand(encodedList string) (Bitstring, error) {
	// base64 decode
	// the examples contain '-' from which I took that is uses URLEncoding over StdEncoding
	compressed, err := base64.URLEncoding.DecodeString(encodedList)
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
