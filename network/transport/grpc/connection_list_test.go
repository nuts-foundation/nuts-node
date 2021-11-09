package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_connectionList_closeAll(t *testing.T) {
	cn := connectionList{}
	connA, _ := cn.getOrRegister(transport.Peer{ID: "a"}, nil)
	closerA := connA.closer()
	connB, _ := cn.getOrRegister(transport.Peer{ID: "b"}, nil)
	closerB := connB.closer()
	cn.closeAll()

	assert.Len(t, closerA, 1)
	assert.Len(t, closerB, 1)
}

func Test_connectionList_getOrRegister(t *testing.T) {
	t.Run("second call with same peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA, created1 := cn.getOrRegister(transport.Peer{ID: "a"}, nil)
		assert.True(t, created1)
		connASecondCall, created2 := cn.getOrRegister(transport.Peer{ID: "a"}, nil)
		assert.False(t, created2)
		assert.Equal(t, connA, connASecondCall)
	})
	t.Run("call with other peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA, created1 := cn.getOrRegister(transport.Peer{ID: "a"}, nil)
		assert.True(t, created1)
		connB, created2 := cn.getOrRegister(transport.Peer{ID: "b"}, nil)
		assert.True(t, created2)
		assert.NotEqual(t, connA, connB)
	})
}

func Test_connectionList_remove(t *testing.T) {
	cn := connectionList{}
	connA, _ := cn.getOrRegister(transport.Peer{ID: "a"}, nil)
	connB, _ := cn.getOrRegister(transport.Peer{ID: "b"}, nil)
	connC, _ := cn.getOrRegister(transport.Peer{ID: "c"}, nil)

	assert.Len(t, cn.list, 3)
	cn.remove(connB)
	assert.Len(t, cn.list, 2)
	assert.Contains(t, cn.list, connA)
	assert.Contains(t, cn.list, connC)
}
