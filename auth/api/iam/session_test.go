package iam

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestServerState(t *testing.T) {
	vpStr := `{"type":"VerifiablePresentation", "id":"vp", "verifiableCredential":{"type":"VerifiableCredential", "id":"vc", "credentialSubject":{"id":"did:web:example.com:iam:holder"}}}`
	expectedVP, err := vc.ParseVerifiablePresentation(vpStr)
	require.NoError(t, err)
	require.NotEmpty(t, expectedVP.ID.String())
	require.NotEmpty(t, expectedVP.VerifiableCredential[0].ID.String())
	submissionAsStr := `{"id":"1", "definition_id":"1", "descriptor_map":[{"id":"1","format":"ldp_vc","path":"$.verifiableCredential"}]}`
	var expectedSubmission pe.PresentationSubmission
	err = json.Unmarshal([]byte(submissionAsStr), &expectedSubmission)
	require.NoError(t, err)

	state := ServerState{}
	state[presentationsStateKey] = []vc.VerifiablePresentation{*expectedVP}
	state[submissionStateKey] = expectedSubmission
	state[credentialMapStateKey] = map[string]vc.VerifiableCredential{"1": expectedVP.VerifiableCredential[0]}

	t.Run("before marshalling", func(t *testing.T) {
		actualVPs := state.VerifiablePresentations()
		require.Len(t, actualVPs, 1)
		require.Equal(t, *expectedVP, actualVPs[0])

		actualSubmission := state.PresentationSubmission()
		require.NotNil(t, actualSubmission)
		require.Equal(t, expectedSubmission, *actualSubmission)

		actualCredentialMap := state.CredentialMap()
		require.Len(t, actualCredentialMap, 1)
		require.Equal(t, expectedVP.VerifiableCredential[0], actualCredentialMap["1"])
	})
	t.Run("after marshalling", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store := storageEngine.GetSessionDatabase().GetStore(time.Minute, "session")

		err := store.Put("state", state)
		require.NoError(t, err)
		var actualState ServerState
		err = store.Get("state", &actualState)
		require.NoError(t, err)

		actualVPs := actualState.VerifiablePresentations()
		require.Len(t, actualVPs, 1)
		require.Equal(t, expectedVP.ID.String(), actualVPs[0].ID.String())

		actualSubmission := actualState.PresentationSubmission()
		require.NotNil(t, actualSubmission)
		require.Equal(t, expectedSubmission, *actualSubmission)

		actualCredentialMap := actualState.CredentialMap()
		require.Len(t, actualCredentialMap, 1)
		require.Equal(t, expectedVP.VerifiableCredential[0].ID.String(), actualCredentialMap["1"].ID.String())
	})
}
