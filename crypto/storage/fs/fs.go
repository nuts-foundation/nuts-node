/*
 * Nuts node
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
 */

package fs

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/util"
)

type entryType string

// StorageType is the name of this storage type, used in health check reports and configuration.
const StorageType = "fs"

const (
	privateKeyEntry entryType = "private.pem"
)

type fileOpenError struct {
	filePath string
	kid      string
	err      error
}

// Error returns the string representation
func (f *fileOpenError) Error() string {
	return fmt.Sprintf("could not open entry %s with filename %s: %v", f.kid, f.filePath, f.err)
}

// Unwrap is needed for fileOpenError to be UnWrapped
func (f *fileOpenError) Unwrap() error {
	return f.err
}

type fileSystemBackend struct {
	fspath string
}

func (fsc fileSystemBackend) Name() string {
	return StorageType
}

func (fsc fileSystemBackend) CheckHealth() map[string]core.Health {
	return map[string]core.Health{
		"filesystem": {Status: core.HealthStatusUp},
	}
}

// NewFileSystemBackend creates a new filesystem backend, all directories will be created for the given path
// Using a filesystem backend in production is not recommended!
func NewFileSystemBackend(fspath string) (spi.Storage, error) {
	if fspath == "" {
		return nil, errors.New("filesystem path is empty")
	}
	fsc := &fileSystemBackend{
		fspath,
	}

	// Assert base directory is present
	err := os.MkdirAll(fsc.fspath, 0700)
	if err != nil {
		return nil, err
	}

	return fsc, nil
}

func (fsc fileSystemBackend) PrivateKeyExists(kid string) bool {
	_, err := os.Stat(fsc.getEntryPath(kid, privateKeyEntry))
	return err == nil
}

// GetPrivateKey loads the private key for the given legalEntity from disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc fileSystemBackend) GetPrivateKey(kid string) (crypto.Signer, error) {
	data, err := fsc.readEntry(kid, privateKeyEntry)
	if err != nil {
		return nil, err
	}
	privateKey, err := util.PemToPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// SavePrivateKey saves the private key for the given key to disk. Files are postfixed with '_private.pem'. Keys are stored in pem format.
func (fsc fileSystemBackend) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	filenamePath := fsc.getEntryPath(kid, privateKeyEntry)
	outFile, err := os.OpenFile(filenamePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0600))

	if err != nil {
		return err
	}

	defer outFile.Close()

	pem, err := util.PrivateKeyToPem(key)
	if err != nil {
		return err
	}

	_, err = outFile.Write([]byte(pem))

	return err
}

func (fsc fileSystemBackend) ListPrivateKeys() []string {
	var result []string
	err := filepath.Walk(fsc.fspath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), string(privateKeyEntry)) {
			upper := len(info.Name()) - len(privateKeyEntry) - 1
			if upper > 0 {
				result = append(result, info.Name()[:upper])
			}
		}
		return nil
	})
	if err != nil {
		log.Logger().
			WithError(err).
			Errorf("Error while listing private keys in %s", fsc.fspath)
	}
	return result
}

func (fsc fileSystemBackend) readEntry(kid string, entryType entryType) ([]byte, error) {
	filePath := fsc.getEntryPath(kid, entryType)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &fileOpenError{kid: kid, filePath: filePath, err: spi.ErrNotFound}
		}
		return nil, &fileOpenError{kid: kid, filePath: filePath, err: err}
	}
	return data, nil
}

func (fsc fileSystemBackend) getEntryPath(kid string, entryType entryType) string {
	return filepath.Join(fsc.fspath, getEntryFileName(kid, entryType))
}

func getEntryFileName(kid string, entryType entryType) string {
	return fmt.Sprintf("%s_%s", kid, entryType)
}
