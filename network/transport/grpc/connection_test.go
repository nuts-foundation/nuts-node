package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_connectionList_closeAll(t *testing.T) {
	cn := connectionList{}
	connA := cn.getOrRegister(transport.Peer{ID: "a"}).closer()
	connB := cn.getOrRegister(transport.Peer{ID: "b"}).closer()
	cn.closeAll()

	assert.Len(t, connA, 1)
	assert.Len(t, connB, 1)
}

func Test_connectionList_getOrRegister(t *testing.T) {
	t.Run("second call with same peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA := cn.getOrRegister(transport.Peer{ID: "a"})
		connASecondCall := cn.getOrRegister(transport.Peer{ID: "a"})
		assert.Equal(t, connA, connASecondCall)
	})
	t.Run("call with other peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA := cn.getOrRegister(transport.Peer{ID: "a"})
		connB := cn.getOrRegister(transport.Peer{ID: "b"})
		assert.NotEqual(t, connA, connB)
	})
}

func Test_managedConnection_close(t *testing.T) {
	t.Run("no closers", func(t *testing.T) {
		conn := managedConnection{}
		conn.close()
		assert.Empty(t, conn.closers)
	})
	t.Run("multiple closers", func(t *testing.T) {
		conn := managedConnection{}
		c1 := conn.closer()
		c2 := conn.closer()
		conn.close()
		assert.Len(t, c1, 1)
		assert.Len(t, c2, 1)
	})
	t.Run("multiple calls does not block", func(t *testing.T) {
		conn := managedConnection{}
		c := conn.closer()
		conn.close()
		conn.close()
		conn.close()
		conn.close()
		assert.Len(t, c, 1)
	})
}