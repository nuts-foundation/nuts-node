/*
 * Copyright (C) 2021 Nuts community
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

package cmd

import (
	"bytes"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/require"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	flags := FlagSet()
	assert.NotEmpty(t, flags)
}

func TestGenToken(t *testing.T) {
	const daysValid = 365
	testDirectory := io.TestDirectory(t)
	t.Setenv("NUTS_DATADIR", testDirectory)
	t.Setenv("NUTS_CRYPTO_STORAGE", "fs")

	outBuf := new(bytes.Buffer)
	cmd := ServerCmd()
	cmd.Commands()[0].Flags().AddFlagSet(core.FlagSet())
	cmd.SetOut(outBuf)
	cmd.SetArgs([]string{"gen-token", "admin", strconv.Itoa(daysValid)})

	err := cmd.Execute()

	output := outBuf.String()
	println(output)
	assert.NoError(t, err)

	matches := regexp.MustCompile("Token:\n\n(.*)\n").FindStringSubmatch(output)
	assert.Len(t, matches, 2)
	token := matches[1]
	parsedToken, err := jwt.Parse([]byte(token), jwt.WithVerify(false))
	require.NoError(t, err)
	assert.Less(t, parsedToken.Expiration(), time.Now().AddDate(0, 0, daysValid+1))
	assert.Greater(t, parsedToken.Expiration(), time.Now().AddDate(0, 0, daysValid-1))
	assert.Equal(t, "admin", parsedToken.Subject())
}
