/*
 * Copyright (C) 2024 Nuts community
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

package storage

import (
	"fmt"
	"github.com/daangn/minimemcached"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_newMemcachedClient(t *testing.T) {
	port, err := getRandomAvailablePort()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &minimemcached.Config{
		Port: uint16(port),
	}
	m, err := minimemcached.Run(cfg)
	if err != nil {
		t.Fatal(err)
	}

	client, err := newMemcachedClient(MemcachedConfig{Address: []string{
		fmt.Sprintf("localhost:%d", m.Port()),
	}})

	defer client.Close()
	defer m.Close()

	require.NoError(t, err)
	require.NotNil(t, client)
}
