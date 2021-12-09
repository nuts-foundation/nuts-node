package doc

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_MakeServiceReference(t *testing.T) {
	d, _ := did.ParseDID("did:nuts:abc")
	assert.Equal(t, "did:nuts:abc/serviceEndpoint?type=hello", MakeServiceReference(*d, "hello").String())
}

func Test_IsServiceReference(t *testing.T) {
	assert.True(t, IsServiceReference("did:nuts:bla"))
	assert.False(t, IsServiceReference("nuts:did:not-a-did"))
}

func Test_ValidateServiceReference(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t")
		err := ValidateServiceReference(*ref)
		assert.NoError(t, err)
	})
	t.Run("error - invalid path", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpointWithInvalidPostfix?type=sajdklsad")
		err := ValidateServiceReference(*ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery)
	})
	t.Run("error - too many type params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t1&type=t2")
		err := ValidateServiceReference(*ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery)
	})
	t.Run("error - no type params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint")
		err := ValidateServiceReference(*ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery)
	})
	t.Run("error - invalid params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t1&someOther=not-allowed")
		err := ValidateServiceReference(*ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery)
	})
}
