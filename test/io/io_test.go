package io

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_normalizeTestName(t *testing.T) {
	t.Run("level 1!@#!@3", func(t *testing.T) {
		t.Run("level 2!!", func(t *testing.T) {
			assert.Equal(t, "Test_normalizeTestName_level_1_____3_level_2__", normalizeTestName(t))
		})
	})
}
