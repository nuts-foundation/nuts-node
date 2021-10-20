package crl

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSyncError_Error(t *testing.T) {
	err := &SyncError{errors: []error{
		errors.New("one"),
		errors.New("two"),
	}}

	assert.Equal(t, "synchronization failed: one, two", err.Error())
}

func TestSyncError_Errors(t *testing.T) {
	oneAndTwo := []error{
		errors.New("one"),
		errors.New("two"),
	}

	err := &SyncError{errors: oneAndTwo}

	assert.Equal(t, oneAndTwo, err.Errors())
}
