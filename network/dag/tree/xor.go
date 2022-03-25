package tree

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

func xor(dest, left, right []byte) {
	for i := 0; i < len(left); i++ {
		dest[i] = left[i] ^ right[i]
	}
}

// Xor is an alias of hash.SHA256Hash that implements tree.Data to track transaction xors
type Xor hash.SHA256Hash

// NewXor returns new(Xor). Convenience function to provide a consistent interface
func NewXor() *Xor {
	return new(Xor)
}

// Hash returns a copy as a hash.SHA256Hash
func (x Xor) Hash() hash.SHA256Hash {
	return hash.SHA256Hash(x)
}

func (x Xor) New() Data {
	return new(Xor)
}

func (x *Xor) Clone() Data {
	c := new(Xor)
	copy(c[:], x[:])
	return c
}

func (x *Xor) Insert(ref hash.SHA256Hash) error {
	xor(x[:], x[:], ref[:])
	return nil
}

func (x *Xor) Add(data Data) error {
	return x.Subtract(data)
}

func (x *Xor) Subtract(data Data) error {
	switch v := data.(type) {
	case *Xor:
		xor(x[:], x[:], v[:])
		return nil
	default:
		return fmt.Errorf("data type mismatch - expected %T, got %T", x, v)
	}
}

func (x Xor) MarshalBinary() ([]byte, error) {
	return x.Clone().(*Xor)[:], nil
}

func (x *Xor) UnmarshalBinary(data []byte) error {
	if len(data) != hash.SHA256HashSize {
		return errors.New("invalid data length")
	}
	copy(x[:], data)
	return nil
}
