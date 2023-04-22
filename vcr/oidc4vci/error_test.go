package oidc4vci

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		assert.EqualError(t, Error{Err: errors.New("token has expired"), Code: InvalidToken}, "invalid_token: token has expired")
	})
	t.Run("without underlying error", func(t *testing.T) {
		assert.EqualError(t, Error{Code: InvalidToken}, "invalid_token")
	})
}
