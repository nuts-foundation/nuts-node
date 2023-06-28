/*
 * Nuts node
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

package jsonld

import (
	"errors"
	"fmt"
)

// Scalar represents a JSON-LD scalar (string, number, true or false)
type Scalar interface {
	fmt.Stringer
	// Value returns the underlying value (string, float, true or false)
	Value() interface{}
	// Equal compares the value of both Scalar
	Equal(o Scalar) bool
}

// StringScalar is the string version of a Scalar
type StringScalar string

func (ss StringScalar) String() string {
	return string(ss)
}

func (ss StringScalar) Value() interface{} {
	return string(ss)
}

func (ss StringScalar) Equal(o Scalar) bool {
	v, ok := o.(StringScalar)
	return ok && v == ss
}

// BoolScalar is the boolean version of a Scalar
type BoolScalar bool

func (bs BoolScalar) String() string {
	if bs {
		return "true"
	}
	return "false"
}

func (bs BoolScalar) Value() interface{} {
	return bool(bs)
}

func (bs BoolScalar) Equal(o Scalar) bool {
	v, ok := o.(BoolScalar)
	return ok && v == bs
}

// Float64Scalar is the float64 version of a Scalar
type Float64Scalar float64

func (fs Float64Scalar) String() string {
	return fmt.Sprintf("%f", float64(fs))
}

func (fs Float64Scalar) Value() interface{} {
	return float64(fs)
}

func (fs Float64Scalar) Equal(o Scalar) bool {
	v, ok := o.(Float64Scalar)
	return ok && v == fs
}

// ErrInvalidValue is returned when an invalid value is parsed
var ErrInvalidValue = errors.New("invalid value")

// ParseScalar returns a Scalar based on an interface value. It returns ErrInvalidValue for unsupported values.
func ParseScalar(value interface{}) (Scalar, error) {
	switch castValue := value.(type) {
	case bool:
		return BoolScalar(castValue), nil
	case string:
		return StringScalar(castValue), nil
	case float64:
		return Float64Scalar(castValue), nil
	}

	return nil, ErrInvalidValue
}

// MustParseScalar returns a Scalar based on an interface value. It panics when the value is not supported.
func MustParseScalar(value interface{}) Scalar {
	s, err := ParseScalar(value)
	if err != nil {
		panic(err)
	}
	return s
}
