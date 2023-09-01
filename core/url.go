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

package core

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// JoinURLPaths works like path.Join but for URLs; it won't remove double slashes.
// It makes sures there is only one slash between the parts.
func JoinURLPaths(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		result = strings.TrimSuffix(result, "/") + "/" + strings.TrimPrefix(parts[i], "/")
	}
	return result
}

// ParsePublicURL parses the given input string as URL and asserts that
// it has a scheme and that it is in the allowedSchemes if provided,
// it is not an IP address, and
// it is not (depending on allowReserved) a reserved address or TLD as described in RFC2606 or https://www.ietf.org/archive/id/draft-chapin-rfc2606bis-00.html.
func ParsePublicURL(input string, allowReserved bool, allowedSchemes ...string) (*url.URL, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Hostname() == "" {
		return nil, errors.New("url must contain scheme and host")
	}
	if len(allowedSchemes) > 0 && !slices.Contains(allowedSchemes, parsed.Scheme) {
		return nil, fmt.Errorf("scheme must be %s", strings.Join(allowedSchemes, " or "))
	}
	if net.ParseIP(parsed.Hostname()) != nil {
		return nil, errors.New("hostname is IP")
	}
	if !allowReserved && isReserved(parsed) {
		return nil, errors.New("hostname is RFC2606 reserved")
	}
	return parsed, nil
}

// isReserved returns true if URL uses any of the reserved TLDs or addresses
func isReserved(URL *url.URL) bool {
	parts := strings.Split(strings.ToLower(URL.Hostname()), ".")
	tld := parts[len(parts)-1]
	if slices.Contains(reservedTLDs, tld) {
		return true
	}

	if len(parts) > 1 {
		l2address := strings.Join(parts[len(parts)-2:], ".")
		return slices.Contains(reservedAddresses, l2address)
	}

	return false
}

var reservedTLDs = []string{
	"", // no domain specified
	"corp",
	"example",
	"home",
	"host",
	"invalid",
	"lan",
	"local",
	"localdomain",
	"localhost",
	"test",
}
var reservedAddresses = []string{
	"example.com",
	"example.net",
	"example.org",
}
