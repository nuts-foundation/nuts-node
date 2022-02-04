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

package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type Predicate func() (bool, error)

func WaitFor(t *testing.T, p Predicate, timeout time.Duration, message string, msgArgs ...interface{}) bool {
	deadline := time.Now().Add(timeout)
	for {
		b, err := p()
		if !assert.NoError(t, err) {
			return false
		}
		if b {
			return true
		}
		if time.Now().After(deadline) {
			assert.Fail(t, fmt.Sprintf(message, msgArgs...))
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func WaitForNoFail(t *testing.T, p Predicate, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		b, err := p()
		if !assert.NoError(t, err) {
			return false
		}
		if b {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
