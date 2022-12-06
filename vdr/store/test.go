/*
 * Copyright (C) 2022 Nuts community
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

package store

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/require"
	"path"
	"testing"
)

const moduleName = "VDR"

// TestDIDA is a testDID
var TestDIDA = did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

// TestDIDB is a testDID
var TestDIDB = did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

func NewTestStore(t *testing.T) *store {
	storageEngine := storage.NewTestStorageEngine(path.Join(io.TestDirectory(t)))
	s := NewStore(storageEngine.GetProvider(moduleName), true).(*store)
	err := s.Configure(core.ServerConfig{})
	require.NoError(t, err)
	return s
}
