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
 *
 */

package v1

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/credential"
	"github.com/nuts-foundation/nuts-node/credential/concept"
	"github.com/nuts-foundation/nuts-node/mock"
)

type mockContext struct {
	ctrl     *gomock.Controller
	echo     *mock.MockContext
	registry *concept.MockRegistry
	reader   *credential.MockVCReader
	client   *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	registry := concept.NewMockRegistry(ctrl)
	reader := credential.NewMockVCReader(ctrl)
	client := &Wrapper{CR: registry, R: reader}

	return mockContext{
		ctrl:     ctrl,
		echo:     mock.NewMockContext(ctrl),
		registry: registry,
		reader:   reader,
		client:   client,
	}
}
