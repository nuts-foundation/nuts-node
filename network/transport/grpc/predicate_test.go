package grpc

import (
	"github.com/nuts-foundation/go-did/did"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByPeerID(t *testing.T) {
	assert.True(t, ByPeerID("123").Match(&StubConnection{PeerID: "123"}))
	assert.False(t, ByPeerID("123").Match(&StubConnection{PeerID: "anything-else"}))
}

func TestByNodeDID(t *testing.T) {
	did1, _ := did.ParseDID("did:nuts:123")
	did2, _ := did.ParseDID("did:nuts:456")

	assert.True(t, ByNodeDID(*did1).Match(&StubConnection{NodeDID: *did1}))
	assert.False(t, ByNodeDID(*did2).Match(&StubConnection{NodeDID: *did1}))
}

func TestByConnected(t *testing.T) {
	assert.True(t, ByConnected().Match(&StubConnection{Open: true}))
	assert.False(t, ByConnected().Match(&StubConnection{}))
}

func TestByNotConnected(t *testing.T) {
	assert.True(t, ByNotConnected().Match(&StubConnection{}))
	assert.False(t, ByNotConnected().Match(&StubConnection{Open: true}))
}
