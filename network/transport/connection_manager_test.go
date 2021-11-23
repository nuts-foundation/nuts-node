package transport

import (
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/go-did/did"
	"testing"
)

func TestFixedNodeDIDResolver_Resolve(t *testing.T) {
	expected, _ := did.ParseDID("did:nuts:test")
	actual, _ := FixedNodeDIDResolver{NodeDID: *expected}.Resolve()
	assert.Equal(t, actual.String(), expected.String())
}
