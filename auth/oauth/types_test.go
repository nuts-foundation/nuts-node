package oauth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIssuerIdToWellKnown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/id", u.String())
	})
	t.Run("no path in issuer", func(t *testing.T) {
		issuer := "https://nuts.nl"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server", u.String())
	})
	t.Run("don't unescape path", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/%2E%2E/still-has-iam"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/%2E%2E/still-has-iam", u.String())
	})
	t.Run("https in strictmode", func(t *testing.T) {
		issuer := "http://nuts.nl/iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "scheme must be https")
		assert.Nil(t, u)
	})
	t.Run("no IP allowed", func(t *testing.T) {
		issuer := "https://127.0.0.1/iam/id"

		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)

		assert.ErrorContains(t, err, "hostname is IP")
		assert.Nil(t, u)
	})
	t.Run("invalid URL", func(t *testing.T) {
		issuer := "http:// /iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "invalid character \" \" in host name")
		assert.Nil(t, u)
	})
}
