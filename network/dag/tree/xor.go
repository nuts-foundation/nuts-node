/*
 * Copyright (C) 2022 Nuts community
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

package tree

import (
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// Xor is an alias of hash.SHA256Hash that implements tree.Data to track transaction xors
type Xor hash.SHA256Hash

// NewXor returns new(Xor). Convenience function to provide a consistent interface
func NewXor() *Xor {
	return new(Xor)
}

// Hash returns a copy as a hash.SHA256Hash
func (x *Xor) Hash() hash.SHA256Hash {
	return hash.SHA256Hash(*x).Clone()
}

func (x *Xor) New() Data {
	return new(Xor)
}

func (x *Xor) Clone() Data {
	c := new(Xor)
	copy(c[:], x[:])
	return c
}

func (x *Xor) Insert(ref hash.SHA256Hash) {
	x.xor(ref)
}

func (x *Xor) Delete(ref hash.SHA256Hash) {
	x.xor(ref)
}

func (x *Xor) Add(data Data) error {
	return x.Subtract(data)
}

func (x *Xor) Subtract(data Data) error {
	switch v := data.(type) {
	case *Xor:
		x.xor(v.Hash())
		return nil
	default:
		return fmt.Errorf("data type mismatch - expected %T, got %T", x, v)
	}
}

func (x *Xor) Empty() bool {
	return *x == Xor{}
}

func (x *Xor) MarshalBinary() ([]byte, error) {
	return x.Clone().(*Xor)[:], nil
}

func (x *Xor) UnmarshalBinary(data []byte) error {
	if len(data) != hash.SHA256HashSize {
		return errors.New("invalid data length")
	}
	copy(x[:], data)
	return nil
}

// in-place xor operation
func (x *Xor) xor(other hash.SHA256Hash) {
	copy(x[:], x.Hash().Xor(other).Slice())
}
