/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package didweb

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"net/url"
	"strings"
)

var errInvalidWebDIDURL = errors.New("URL does not represent a Web DID")

// URLToDID converts a URL back to a Web DID (did:web). It removes /did.json and /.well-known/did.json from the path, if present.
// Examples:
// - https://localhost/.well-known/did.json -> did:web:localhost
// - https://localhost/alice+and+bob/path/did.json -> did:web:localhost:alice%2Band%2Bbob:path
// - https://localhost:3000/alice -> did:web:localhost%3A3000:alice
func URLToDID(u url.URL) (*did.DID, error) {
	path := u.Path
	if u.RawPath != "" {
		// In case the path contains encoded characters, RawPath must be used. But it's only populated in this case.
		path = u.RawPath
	}
	path, _ = strings.CutSuffix(path, "/.well-known/did.json")
	path, _ = strings.CutSuffix(path, "/did.json")
	parts := strings.Split(path, "/")
	for i, part := range parts {
		part = percentEncodeString(part)
		parts[i] = part
	}
	str := "did:web:" + percentEncodeString(u.Host) + strings.Join(parts, ":")
	result, err := did.ParseDID(str)
	if err != nil {
		return nil, errors.Join(errInvalidWebDIDURL, err)
	}
	return result, nil
}

// percentEncodeString applies percent-encoding to all subjective characters in a DID-specific ID string.
// It is inspired by url.PathEscape, but the DID syntax disallows more characters than the URL syntax.
func percentEncodeString(s string) string {
	const upperhex = "0123456789ABCDEF"
	length := lengthAfterPercentEncoding(s)
	if length == len(s) {
		// Nothing to encode
		return s
	}
	result := make([]byte, length)
	j := 0
	for _, c := range s {
		if shouldPercentEncode(c) {
			result[j] = '%'
			result[j+1] = upperhex[c>>4]
			result[j+2] = upperhex[c&15]
			j += 3
		} else {
			result[j] = byte(c)
			j++
		}
	}
	return string(result)
}

func lengthAfterPercentEncoding(s string) int {
	var count int
	for _, c := range s {
		if shouldPercentEncode(c) {
			count += 3
		} else {
			count++
		}
	}
	return count
}

func shouldPercentEncode(c rune) bool {
	switch c {
	case '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@':
		return true
	}
	return false
}
