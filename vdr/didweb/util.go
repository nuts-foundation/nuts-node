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
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"net"
	"net/url"
	"strings"
)

var errInvalidWebDIDURL = errors.New("URL does not represent a Web DID")

// URLToDID converts a URL back to a Web DID (did:web). It removes /did.json and /.well-known/did.json from the path, if present.
// Examples:
// - https://localhost/.well-known/did.json -> did:web:localhost
// - https://localhost/alice+and+bob/path/did.json -> did:web:localhost:alice%2Band%2Bbob:path
// - https://localhost:3000/alice -> did:web:localhost%3A3000:alice
// - https://nodeA/iam/5/ -> did:web:nodeA:iam:5
func URLToDID(u url.URL) (*did.DID, error) {
	path := u.Path
	if u.RawPath != "" {
		// In case the path contains encoded characters, RawPath must be used. But it's only populated in this case.
		path = u.RawPath
	}
	path, _ = strings.CutSuffix(path, "/.well-known/did.json")
	path, _ = strings.CutSuffix(path, "/did.json")
	parts := strings.Split(path, "/")
	j := 0
	for _, part := range parts {
		if len(part) > 0 {
			part = percentEncodeString(part)
			parts[j] = part
			j++
		}
	}
	parts = parts[:j]
	str := "did:web:" + percentEncodeString(u.Host)
	if len(parts) > 0 {
		str += ":" + strings.Join(parts, ":")
	}
	result, err := did.ParseDID(str)
	if err != nil {
		return nil, errors.Join(errInvalidWebDIDURL, err)
	}
	return result, nil
}

// DIDToURL converts a Web DID (did:web) to a URL.
// Examples:
// - did:web:localhost -> https://localhost
// - did:web:localhost:alice%2Band%2Bbob:path -> https://localhost/alice+and+bob/path
// - did:web:localhost%3A3000:alice -> https://localhost:3000/alice
func DIDToURL(id did.DID) (*url.URL, error) {
	if id.Method != "web" {
		return nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}
	var baseID = id.ID
	var path string
	subpathIdx := strings.Index(id.ID, ":")
	if subpathIdx != -1 {
		// subpaths are encoded as / -> :
		baseID = id.ID[:subpathIdx]
		path = id.ID[subpathIdx:]
		path = strings.ReplaceAll(path, ":", "/")
		// Paths can't be empty; it should not contain subsequent slashes, or end with a slash
		if strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			return nil, fmt.Errorf("invalid did:web: contains empty path elements")
		}
	}

	unescapedID, err := url.PathUnescape(baseID)
	if err != nil {
		return nil, fmt.Errorf("invalid did:web: %w", err)
	}
	// only certain chars allowed, '/' for example may not be unescaped
	unescapedPath := percentDecodeString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid did:web: %w", err)
	}
	targetURL := "https://" + unescapedID + unescapedPath

	// Use url.Parse() to check that;
	// - the DID does not contain a sneaky percent-encoded path or other illegal stuff
	// - the DID does not contain an IP address
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		// came from a DID, not sure how it could fail
		return nil, err
	}
	if parsedURL.Host != unescapedID {
		return nil, fmt.Errorf("invalid did:web: illegal characters in domain name")
	}
	parsedIP := net.ParseIP(parsedURL.Hostname())
	if parsedIP != nil {
		return nil, fmt.Errorf("invalid did:web: ID must be a domain name, not IP address")
	}
	return parsedURL, nil
}

// percentDecodeString decodes all percent-encoded characters in a DID-specific ID string.
func percentDecodeString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if c, ok := percentDecodeChar(s[i : i+3]); ok {
				result = append(result, c)
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result)
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f')
}

func unhex(c byte) byte {
	if '0' <= c && c <= '9' {
		return c - '0'
	}
	if 'A' <= c && c <= 'F' {
		return c - 'A' + 10
	}
	return c - 'a' + 10
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

func percentDecodeChar(encoded string) (byte, bool) {
	if len(encoded) != 3 {
		return ' ', false
	}
	if encoded[0] != '%' {
		return ' ', false
	}
	a := encoded[1]
	b := encoded[2]
	if !isHex(a) || !isHex(b) {
		return ' ', false
	}
	c := unhex(a)*16 + unhex(b)
	switch c {
	case '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@':
		return c, true
	}
	return ' ', false
}
