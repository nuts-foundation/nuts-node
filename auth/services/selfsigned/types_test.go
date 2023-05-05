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

package selfsigned

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_newVerificationError(t *testing.T) {
	err := newVerificationError("test")

	assert.Equal(t, "test", err.Error(), "unexpected error message")
}

func Test_verificationError_Error(t *testing.T) {
	e := newVerificationError("test")

	assert.Equal(t, "test", e.Error(), "unexpected error message")
}

func Test_verificationError_Is(t *testing.T) {
	e := newVerificationError("test")

	assert.True(t, errors.Is(e, verificationError{}), "expected error to be of type verificationError")
	assert.False(t, errors.Is(e, errors.New("test")), "expected error to not be of type verificationError")
}

func Test_sessionPointer_MarshalJSON(t *testing.T) {
	ptr := sessionPointer{
		sessionID: "sessionID",
		url:       "url",
	}

	b, err := ptr.MarshalJSON()

	assert.NoError(t, err, "unexpected marshaller error")
	assert.Equal(t, []byte(`{"sessionID":"sessionID","url":"url"}`), b, "unexpected marshalled bytes")
}

func Test_sessionPointer_Payload(t *testing.T) {
	ptr := sessionPointer{
		sessionID: "sessionID",
		url:       "url",
	}

	assert.Equal(t, []byte("url"), ptr.Payload(), "unexpected payload")
}

func Test_sessionPointer_SessionID(t *testing.T) {
	ptr := sessionPointer{
		sessionID: "sessionID",
		url:       "url",
	}

	assert.Equal(t, "sessionID", ptr.SessionID(), "unexpected sessionID")
}

func Test_signingSessionResult_Status(t *testing.T) {
	result := signingSessionResult{
		id:     "id",
		status: "status",
	}

	assert.Equal(t, "status", result.Status(), "unexpected status")
}
