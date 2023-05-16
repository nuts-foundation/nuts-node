package v2

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_Marshalling(t *testing.T) {
	t.Run("IssueVC200JSONResponse", func(t *testing.T) {
		r := IssueVC200JSONResponse{
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": "did:nuts:123",
				}},
		}
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["credentialSubject"]) // single entry should not end up as slice
	})
	t.Run("ResolveVC200JSONResponse", func(t *testing.T) {
		r := ResolveVC200JSONResponse{
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": "did:nuts:123",
				}},
		}
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["credentialSubject"]) // single entry should not end up as slice
	})
	t.Run("CreateVP200JSONResponse", func(t *testing.T) {
		r := CreateVP200JSONResponse{
			VerifiableCredential: []VerifiableCredential{
				{
					IssuanceDate: time.Now(),
				},
			},
		}
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["verifiableCredential"]) // single entry should not end up as slice
	})
}
