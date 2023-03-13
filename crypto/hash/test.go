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

package hash

import (
	"math/rand"

	"github.com/golang/mock/gomock"
)

func EqHash(hash SHA256Hash) gomock.Matcher {
	return &hashMatcher{expected: hash}
}

type hashMatcher struct {
	expected SHA256Hash
}

func (h hashMatcher) Matches(x interface{}) bool {
	if actual, ok := x.(SHA256Hash); !ok {
		return false
	} else {
		return actual.Equals(h.expected)
	}
}

func (h hashMatcher) String() string {
	return "Hash matches: " + h.expected.String()
}

// RandomHash returns a Hash that is initialized with math/rand.
// So NOT a cryptographic secure random Hash, but does generate reproducible results in tests.
func RandomHash() SHA256Hash {
	h := EmptyHash()
	_, _ = rand.Read(h[:])
	return h
}
