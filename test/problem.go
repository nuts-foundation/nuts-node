/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
 */

package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	problem2 "schneider.vip/problem"
	"testing"
)

// problem is a helper struct to Unmarshal problem.Problem
type problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// errorToProblem returns a problem generated from a problem.Problem
// problem.Problem doesn't expose its fields
func errorToProblem(err error) problem {
	prb := problem{}
	b, _ := json.Marshal(err)
	_ = json.Unmarshal(b, &prb)
	return prb
}

// AssertErrIsProblem asserts err is a *problem.Problem
func AssertErrIsProblem(t *testing.T, err error) bool {
	return assert.IsType(t, &problem2.Problem{}, err, "err is not a *problem.Problem")
}

// AssertErrProblemTitle asserts err is a *problem.Problem with the specified title
func AssertErrProblemTitle(t *testing.T, title string, err error) bool {
	if !AssertErrIsProblem(t, err) {
		return false
	}
	prb := errorToProblem(err)
	return assert.Equal(t, title, prb.Title)
}

// AssertErrProblemStatusCode asserts err is a *problem.Problem with the specified status code
func AssertErrProblemStatusCode(t *testing.T, code int, err error) bool {
	if !AssertErrIsProblem(t, err) {
		return false
	}
	prb := errorToProblem(err)
	return assert.Equal(t, code, prb.Status)
}

// AssertErrProblemDetail asserts err is a *problem.Problem with the specified detail
func AssertErrProblemDetail(t *testing.T, detail string, err error) bool {
	if !AssertErrIsProblem(t, err) {
		return false
	}
	prb := errorToProblem(err)
	return assert.Equal(t, detail, prb.Detail)
}
