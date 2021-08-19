package wraperr

import (
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestWrap(t *testing.T) {
	err := Wrap(io.EOF, io.ErrClosedPipe)
	assert.EqualError(t, err, "EOF: io: read/write on closed pipe")
	assert.ErrorIs(t, err, io.EOF)
	assert.ErrorIs(t, err, io.ErrClosedPipe)
	assert.NotErrorIs(t, err, io.ErrNoProgress)
}

