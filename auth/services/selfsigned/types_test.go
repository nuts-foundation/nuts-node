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
