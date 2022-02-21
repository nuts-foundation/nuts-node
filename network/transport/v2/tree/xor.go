package tree

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

func xor(dest *hash.SHA256Hash, left, right hash.SHA256Hash) {
	for i := 0; i < len(left); i++ {
		dest[i] = left[i] ^ right[i]
	}
}

// XorHash is an implementation of tree.Data for xor of transaction references
type XorHash struct {
	Hash hash.SHA256Hash `json:"hash"`
}

func NewXor() Data {
	return &XorHash{Hash: hash.EmptyHash()}
}

func (x XorHash) New() Data {
	return NewXor()
}

func (x *XorHash) Clone() Data {
	clone := x.New()
	_ = clone.Insert(x.Hash)
	return clone
}

func (x *XorHash) Insert(ref hash.SHA256Hash) error {
	xor(&x.Hash, x.Hash, ref)
	return nil
}

func (x *XorHash) Subtract(data Data) error {
	switch v := data.(type) {
	case *XorHash:
		xor(&x.Hash, x.Hash, v.Hash)
		return nil
	default:
		return fmt.Errorf("subtraction failed - expected type %T, got %T", x, v)
	}
}

func (x XorHash) MarshalBinary() ([]byte, error) {
	return x.Hash.Clone().Slice(), nil
}

func (x *XorHash) UnmarshalBinary(data []byte) error {
	if len(data) != hash.SHA256HashSize {
		return errors.New("invalid data length")
	}
	x.Hash = hash.FromSlice(data)
	return nil
}
