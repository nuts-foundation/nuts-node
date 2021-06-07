package v1

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPeerDiagnostics_MarshalJSON(t *testing.T) {
	t.Run("assert uptime is marshaled in seconds", func(t *testing.T) {
		expected := PeerDiagnostics{Uptime: 1 * time.Hour}

		data, _ := json.Marshal(expected)

		actualAsMap := make(map[string]interface{}, 0)
		json.Unmarshal(data, &actualAsMap)
		assert.Equal(t, 3600, int(actualAsMap["uptime"].(float64)))

		actual := PeerDiagnostics{}
		err := json.Unmarshal(data, &actual)
		assert.NoError(t, err)
		assert.Equal(t, expected.Uptime, actual.Uptime)
	})
}
