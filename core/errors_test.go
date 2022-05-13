package core

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWrapError(t *testing.T) {
	var original = errors.New("original")
	var cause = errors.New("cause")
	wrapped := WrapError(original, cause)
	assert.ErrorIs(t, wrapped, original)
	assert.ErrorIs(t, wrapped, cause)
}

func Test_wrappedError_Error(t *testing.T) {
	wrapped := WrapError(errors.New("original"), errors.New("cause"))
	assert.EqualError(t, wrapped, "original: cause")
}