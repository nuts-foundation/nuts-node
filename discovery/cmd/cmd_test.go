package cmd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFlagSet(t *testing.T) {
	flagset := FlagSet()
	assert.NotNil(t, flagset)
}
