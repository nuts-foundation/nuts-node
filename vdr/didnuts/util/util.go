package util

import ssi "github.com/nuts-foundation/go-did"

// LDContextToString converts a JSON-LD context to a string, if it's a string or a ssi.URI
// If it's not a string or ssi.URI, it will return an empty string.
func LDContextToString(context interface{}) string {
	var result string
	switch ctx := context.(type) {
	case ssi.URI:
		result = ctx.String()
	case string:
		result = ctx
	}
	return result
}
