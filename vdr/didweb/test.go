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
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/require"
	"net/url"
	"strings"
	"testing"
)

func ServerURLToDIDWeb(t *testing.T, stringUrl string) did.DID {
	stringUrl = strings.ReplaceAll(stringUrl, "127.0.0.1", "localhost")
	asURL, err := url.Parse(stringUrl)
	require.NoError(t, err)
	testDID, err := URLToDID(*asURL)
	require.NoError(t, err)
	return *testDID
}
