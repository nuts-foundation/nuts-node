package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNutsAccessToken_FromMap(t *testing.T) {
	expected := NutsAccessToken{Name: "Foobar"}
	asJSON, _ := json.Marshal(&expected)
	var asMap map[string]interface{}
	err := json.Unmarshal(asJSON, &asMap)
	if !assert.NoError(t, err) {
		return
	}
	var actual NutsAccessToken
	err = actual.FromMap(asMap)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
