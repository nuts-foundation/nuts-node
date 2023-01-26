// Package storage provides secret storage for the Crypto module. It contains the following packages:
//   - `spi` (Service Programming Interface): interfaces and types used to implement a secret storage backend.
//   - `fs` (File System): a secret storage backend that stores secrets in the file system. Only to be used in development.
//   - `vault` (Hashicorp Vault): a secret storage backend that stores secrets in a Hashicorp Vault server.
//     Will be removed in a future release, in favor of the `external` storage backend.
//   - `external` (External): a secret storage backend that stores secrets externally (e.g. Vault).
package storage
