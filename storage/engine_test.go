package storage

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_New(t *testing.T) {
	assert.NotNil(t, New())
}

func Test_engine_Name(t *testing.T) {
	assert.Equal(t, "Storage", engine{}.Name())
}
