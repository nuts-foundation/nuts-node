package storage

import (
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
)

var kidPattern = regexp.MustCompile(`^[\da-zA-Z_\- :#.]+$`)

var goodKIDs = []string{
	"admin-token-signing-key",
	"did:nuts:2pgo54Z3ytC5EdjBicuJPe5gHyAsjF6rVio1FadSX74j#GxL7A5XNFr_tHcBW_fKCndGGko8DKa2ivPgJAGR0krA",
	"did:nuts:3dGjPPeEuHsyNMgJwHkGX3HuJkEEnZ8H19qBqTaqLDbt#JwIR4Vct-EELNKeeB0BZ8Uff_rCZIrOhoiyp5LDFl68",
	"did:nuts:BC5MtUzAncmfuGejPFGEgM2k8UfrKZVbbGyFeoG9JEEn#l2swLI0wus8gnzbI3sQaaiE7Yvv2qOUioaIZ8y_JZXs",
}
var badKIDs = []string{
	"../server-certificate",
	"\\",
	"",
	"\t",
}

func TestWrapper(t *testing.T) {
	w := wrapper{kidPattern: kidPattern}

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
	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: kidPattern}
		for _, kid := range badKIDs {
			_, err := w.GetPrivateKey(kid)
			assert.Error(t, err)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, kidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().GetPrivateKey(kid)
			_, err := w.GetPrivateKey(kid)
			assert.NoError(t, err)
		}
		ctrl.Finish()
	})
}

func TestWrapper_PrivateKeyExists(t *testing.T) {

	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: kidPattern}
		for _, kid := range badKIDs {
			exists := w.PrivateKeyExists(kid)
			assert.False(t, exists)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, kidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().PrivateKeyExists(kid).Return(true)
			exists := w.PrivateKeyExists(kid)
			assert.True(t, exists)
		}
		ctrl.Finish()
	})
}

func TestWrapper_SavePrivateKey(t *testing.T) {

	t.Run("expect error for bad KIDs", func(t *testing.T) {
		w := wrapper{kidPattern: kidPattern}
		for _, kid := range badKIDs {
			err := w.SavePrivateKey(kid, nil)
			assert.Error(t, err)
		}
	})
	t.Run("expect call to wrapped backend for good KIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, kidPattern)

		for _, kid := range goodKIDs {
			mockStorage.EXPECT().SavePrivateKey(kid, gomock.Any())
			err := w.SavePrivateKey(kid, nil)
			assert.NoError(t, err)
		}
		ctrl.Finish()
	})
}

func TestWrapper_ListPrivateKeys(t *testing.T) {

	t.Run("expect call to wrapped backend", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStorage := NewMockStorage(ctrl)
		w := NewValidatedKIDBackendWrapper(mockStorage, kidPattern)

		mockStorage.EXPECT().ListPrivateKeys().Return([]string{"foo", "bar"})
		keys := w.ListPrivateKeys()
		assert.Equal(t, []string{"foo", "bar"}, keys)
		ctrl.Finish()
	})
}
