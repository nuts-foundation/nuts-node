package iam

import (
	"strings"
)

// localize selects from a range of localized values based on the accept-language header, returning
// a default value if no localized value matches the languages specified in the accept-language header.
func localize(defaultValue string, localizedValues map[string]string, acceptLanguageHeader string) string {
	// Iterate over the accepted languages specified by the user-agent
	for _, acceptedLanguage := range strings.Split(acceptLanguageHeader, ",") {
		// Trim any whitespace from the language specification
		acceptedLanguage = strings.TrimSpace(acceptedLanguage)

		// Split the language and any associated q-factor value (e.g. "en;q=0.5") where the q-factor specifies
		// the strength of language preference
		languageSpec := strings.Split(strings.TrimSpace(acceptedLanguage), ";")

		// Ignore any q-factors and look for a supported language based on the order of the accepted languages.
		// In most cases there is no difference as user-agents tend to send these in descending order.
		if localizedValue, ok := localizedValues[languageSpec[0]]; ok {
			return localizedValue
		}
	}

	// Return the default value as no localized value matched
	return defaultValue
}
