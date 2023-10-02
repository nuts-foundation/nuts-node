package didkey

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		name string
		id   string
		err  error
	}{
		{
			name: "Ed25519",
			id:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Resolver{}
			got, got1, err := r.Resolve(did.MustParseDID(tt.id), nil)
			if tt.err != nil {
				require.Error(t, err)
				require.Nil(t, got)
				require.Nil(t, got1)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got1)
		})
	}
}
