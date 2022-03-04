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

// Xor is a wrapper around hash.SHA256Hash that implements tree.Data to track transaction xors
type Xor struct {
	Hash hash.SHA256Hash `json:"hash"`
}

func NewXor() *Xor {
	return &Xor{Hash: hash.EmptyHash()}
}

func (x Xor) New() Data {
	return NewXor()
}

func (x *Xor) Clone() Data {
	clone := x.New()
	_ = clone.Insert(x.Hash)
	return clone
}

func (x *Xor) Insert(ref hash.SHA256Hash) error {
	xor(&x.Hash, x.Hash, ref)
	return nil
}

func (x *Xor) Add(data Data) error {
	return x.Subtract(data)
}

func (x *Xor) Subtract(data Data) error {
	switch v := data.(type) {
	case *Xor:
		xor(&x.Hash, x.Hash, v.Hash)
		return nil
	default:
		return fmt.Errorf("data type mismatch - expected %T, got %T", x, v)
	}
}

func (x Xor) MarshalBinary() ([]byte, error) {
	return x.Hash.Clone().Slice(), nil
}

func (x *Xor) UnmarshalBinary(data []byte) error {
	if len(data) != hash.SHA256HashSize {
		return errors.New("invalid data length")
	}
	x.Hash = hash.FromSlice(data)
	return nil
}
