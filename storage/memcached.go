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

import "github.com/bradfitz/gomemcache/memcache"

// MemcachedConfig holds the configuration for the memcached storage.
type MemcachedConfig struct {
	Address []string `koanf:"address"`
}

// isConfigured returns true if config the indicates Redis support should be enabled.
func (r MemcachedConfig) isConfigured() bool {
	return len(r.Address) > 0
}

// newMemcachedClient creates a memcache.Client and performs a Ping()
func newMemcachedClient(config MemcachedConfig) (*memcache.Client, error) {
	client := memcache.New(config.Address...)
	err := client.Ping()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, err
}
