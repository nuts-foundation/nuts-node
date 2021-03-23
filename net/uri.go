package net

import (
	"net/url"
)

// UnescapePathIfEscaped unescapes the given URL path if it is escaped.
func UnescapePathIfEscaped(input string) string {
	unescaped, unescapeErr := url.PathUnescape(input)
	if unescapeErr == nil {
		input = unescaped
	}
	return input
}
