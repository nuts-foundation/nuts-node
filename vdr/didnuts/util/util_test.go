package util

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLDContextToString(t *testing.T) {
	assert.Equal(t, "https://www.w3.org/ns/did/v1", LDContextToString("https://www.w3.org/ns/did/v1"))
	assert.Equal(t, "https://www.w3.org/ns/did/v1", LDContextToString(ssi.MustParseURI("https://www.w3.org/ns/did/v1")))
	assert.Empty(t, LDContextToString(map[string]interface{}{"@base": "123"}))
}
