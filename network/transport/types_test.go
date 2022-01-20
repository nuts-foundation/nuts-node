package transport

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ParseAddress(t *testing.T) {
	t.Run("valid - with port", func(t *testing.T) {
		addr, err := ParseAddress("grpc://foo:5050")
		assert.NoError(t, err)
		assert.Equal(t, "foo:5050", addr)
	})
	t.Run("valid - without port", func(t *testing.T) {
		addr, err := ParseAddress("grpc://foo")
		assert.NoError(t, err)
		assert.Equal(t, "foo", addr)
	})
	t.Run("invalid - no scheme", func(t *testing.T) {
		addr, err := ParseAddress("foo")
		assert.Empty(t, addr)
		assert.EqualError(t, err, "invalid URL scheme")
	})
	t.Run("invalid - invalid scheme", func(t *testing.T) {
		addr, err := ParseAddress("http://foo")
		assert.Empty(t, addr)
		assert.EqualError(t, err, "invalid URL scheme")
	})
}
