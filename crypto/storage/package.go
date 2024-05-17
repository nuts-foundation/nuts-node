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

// Package storage provides secret storage for the Crypto module. It contains the following packages:
//   - `spi` (Service Programming Interface): interfaces and types used to implement a secret storage backend.
//   - `fs` (File System): a secret storage backend that stores secrets in the file system. Only to be used in development.
//   - `vault` (Hashicorp Vault): a secret storage backend that stores secrets in a Hashicorp Vault server.
//     Will be removed in a future release, in favor of the `external` storage backend.
//   - `external` (External): a secret storage backend that stores secrets externally (e.g. Vault).
package storage

import "crypto"

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)
