package transport

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Address(t *testing.T) {
	assert.Equal(t, "", Address("").String())
	assert.Equal(t, "grpc://10.0.0.2:5555", Address("10.0.0.2:5555").String())
}

func Test_ParseAddress(t *testing.T) {
	t.Run("valid - with port", func(t *testing.T) {
		addr, err := ParseAddress("grpc://foo:5050")
		assert.False(t, addr.Empty())
		assert.NoError(t, err)
		assert.Equal(t, "grpc://foo:5050", addr.String())
	})
	t.Run("valid - without port", func(t *testing.T) {
		addr, err := ParseAddress("grpc://foo")
		assert.False(t, addr.Empty())
		assert.NoError(t, err)
		assert.Equal(t, "grpc://foo", addr.String())
	})
	t.Run("invalid - no scheme", func(t *testing.T) {
		addr, err := ParseAddress("foo")
		assert.True(t, addr.Empty())
		assert.EqualError(t, err, "invalid URL scheme")
	})
	t.Run("invalid - invalid scheme", func(t *testing.T) {
		addr, err := ParseAddress("http://foo")
		assert.True(t, addr.Empty())
		assert.EqualError(t, err, "invalid URL scheme")
	})
}

func Test_Addr_Empty(t *testing.T) {
	assert.True(t, Address("").Empty())
	assert.False(t, Address("10.0.0.2:5555").Empty())
}

func Test_Addr_Target(t *testing.T) {
	assert.Equal(t, "foo", Address("foo").Target())
}

func Test_Addr_Scheme(t *testing.T) {
	assert.Equal(t, "grpc", Address("foo").Scheme())
}