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
 *
 */

package spi

import (
	"context"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"testing"
)

var goodKIDs = []string{
	"admin-token-signing-key",
	"did:nuts:2pgo54Z3ytC5EdjBicuJPe5gHyAsjF6rVio1FadSX74j#GxL7A5XNFr_tHcBW_fKCndGGko8DKa2ivPgJAGR0krA",
	"did:nuts:3dGjPPeEuHsyNMgJwHkGX3HuJkEEnZ8H19qBqTaqLDbt#JwIR4Vct-EELNKeeB0BZ8Uff_rCZIrOhoiyp5LDFl68",
	"did:nuts:BC5MtUzAncmfuGejPFGEgM2k8UfrKZVbbGyFeoG9JEEn#l2swLI0wus8gnzbI3sQaaiE7Yvv2qOUioaIZ8y_JZXs",
	"did:web:nodeA%3A10443:iam:aa00a18b-3d6d-46fd-867b-468819437d00#0",
}
var badKIDs = []string{
	"../server-certificate",
	"/etc/passwd",
	"\\",
	"",
	"\t",
}

func TestWrapper(t *testing.T) {
	w := wrapper{kidPattern: KidPattern}

	t.Run("good KIDs", func(t *testing.T) {
		for _, kid := range goodKIDs {
			assert.NoError(t, w.validateKID(kid))
		}
	})
	t.Run("bad KIDs", func(t *testing.T) {
		for _, kid := range badKIDs {
			assert.Error(t, w.validateKID(kid))
		}
	})
}

func TestWrapper_GetPrivateKey(t *testing.T) {
	ctx := context.Background()
	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: KidPattern}
		for _, kid := range badKIDs {
			_, err := w.GetPrivateKey(ctx, kid)
			assert.Error(t, err)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, KidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().GetPrivateKey(ctx, kid)
			_, err := w.GetPrivateKey(ctx, kid)
			assert.NoError(t, err)
		}
		ctrl.Finish()
	})
}

func TestWrapper_PrivateKeyExists(t *testing.T) {
	ctx := context.Background()
	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: KidPattern}
		for _, kid := range badKIDs {
			exists := w.PrivateKeyExists(ctx, kid)
			assert.False(t, exists)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, KidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().PrivateKeyExists(ctx, kid).Return(true)
			exists := w.PrivateKeyExists(ctx, kid)
			assert.True(t, exists)
		}
		ctrl.Finish()
	})
}

func TestWrapper_SavePrivateKey(t *testing.T) {
	ctx := context.Background()
	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: KidPattern}
		for _, kid := range badKIDs {
			err := w.SavePrivateKey(ctx, kid, nil)
			assert.Error(t, err)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, KidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().SavePrivateKey(ctx, kid, gomock.Any())
			err := w.SavePrivateKey(ctx, kid, nil)
			assert.NoError(t, err)
		}
		ctrl.Finish()
	})
}

func Test_wrapper_DeletePrivateKey(t *testing.T) {
	ctx := context.Background()
	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: KidPattern}
		for _, kid := range badKIDs {
			err := w.DeletePrivateKey(ctx, kid)
			assert.Error(t, err)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, KidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().DeletePrivateKey(ctx, kid)
			err := w.DeletePrivateKey(ctx, kid)
			assert.NoError(t, err)
		}
		ctrl.Finish()
	})
}

func TestWrapper_ListPrivateKeys(t *testing.T) {
	ctx := context.Background()
	t.Run("expect call to wrapped backend", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, KidPattern)

		mockStorage.EXPECT().ListPrivateKeys(ctx).Return([]string{"foo", "bar"})
		keys := w.ListPrivateKeys(ctx)
		assert.Equal(t, []string{"foo", "bar"}, keys)
		ctrl.Finish()
	})
}
