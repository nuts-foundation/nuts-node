package dag

import (
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestBBoltPayloadStore_ReadWrite(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	payloadStore := NewBBoltPayloadStore(createBBoltDB(testDirectory))

	payload := []byte("Hello, World!")
	hash := hash.SHA256Sum(payload)
	// Before, payload should not be present
	present, err := payloadStore.IsPresent(hash)
	if !assert.NoError(t, err) || !assert.False(t, present) {
		return
	}
	// Add payload
	err = payloadStore.WritePayload(hash, payload)
	if !assert.NoError(t, err) {
		return
	}
	// Now it should be present
	present, err = payloadStore.IsPresent(hash)
	if !assert.NoError(t, err) || !assert.True(t, present, "payload should be present") {
		return
	}
	// Read payload
	data, err := payloadStore.ReadPayload(hash)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, payload, data)
}

func TestBBoltPayloadStore_Observe(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	payloadStore := NewBBoltPayloadStore(createBBoltDB(testDirectory))

	var actual interface{}
	payloadStore.RegisterObserver(func(subject interface{}) {
		actual = subject
	})
	payload := []byte(t.Name())
	expected := hash.SHA256Sum(payload)
	err := payloadStore.WritePayload(expected, payload)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
