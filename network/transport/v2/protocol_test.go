package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_protocol_Start(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Start()
}

func Test_protocol_Configure(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Configure("")
}

func Test_protocol_Stop(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Stop()
}

func Test_protocol_Diagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.Diagnostics())
}

func Test_protocol_PeerDiagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.PeerDiagnostics())
}
