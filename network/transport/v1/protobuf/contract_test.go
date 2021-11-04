package protobuf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGrpcContract(t *testing.T) {
	// This test asserts the gRPC contract's sanity
	assert.Equal(t, "transport.Network", Network_ServiceDesc.ServiceName)
	assert.Equal(t, "Connect", Network_ServiceDesc.Streams[0].StreamName)
}
