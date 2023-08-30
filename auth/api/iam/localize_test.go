package iam

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalize(t *testing.T) {
	// Define a header where multiple languages are accepted with a mix of implicit & explicit order of preference
	acceptLanguages := "nl, nl-NL, fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"

	// Test the scenario where EN is requested and supported
	t.Run("only en supported", func(t *testing.T) {
		localized := localize("value_default", map[string]string{"en": "value_en"}, acceptLanguages)
		require.Equal(t, localized, "value_en")
	})

	// Test the scenario where none of the accepted languages are supported and the default value is used
	t.Run("no supported languages", func(t *testing.T) {
		localized := localize("value_default", map[string]string{"it": "value_it"}, acceptLanguages)
		require.Equal(t, localized, "value_default")
	})

	// Test the scenario where multiple accepted languages are supported and order of preference is important
	t.Run("multiple supported languages", func(t *testing.T) {
		localized := localize(
			"value_default",
			map[string]string{"nl": "value_nl", "nl-NL": "value_nl-NL", "en": "value_en"},
			acceptLanguages,
		)
		require.Equal(t, localized, "value_nl")
	})

	// Test the scenario when no header is sent
	t.Run("empty accept-languages header", func(t *testing.T) {
		localized := localize("value_default", map[string]string{"it": "value_it"}, "")
		require.Equal(t, localized, "value_default")
	})
}
