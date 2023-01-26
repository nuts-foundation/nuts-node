package external

import "net/url"

// safeKey is used as the Key type in the API.
// It implements the TextMarshaler interface to ensure that the key is URL encoded.
type safeKey string

func (k safeKey) MarshalText() (text []byte, err error) {
	return []byte(url.PathEscape(string(k))), nil
}
