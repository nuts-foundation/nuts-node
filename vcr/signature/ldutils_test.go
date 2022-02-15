package signature

import (
	"embed"
	"errors"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed test/*
var testfs embed.FS

type testLoader struct {
	Called bool
	Err    error
}

func (t *testLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	t.Called = true
	return nil, t.Err
}

func Test_embeddedFSDocumentLoader_LoadDocument(t *testing.T) {

	t.Run("it loads a document", func(t *testing.T) {
		loader := NewEmbeddedFSDocumentLoader(testfs, nil)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("test/test.jsonld")
		assert.NoError(t, err)
		assert.Contains(t, doc.Document, "@context")
	})

	t.Run("it fails when the document is invalid", func(t *testing.T) {
		loader := NewEmbeddedFSDocumentLoader(testfs, nil)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("test/invalid.jsonld")
		assert.Nil(t, doc)
		assert.EqualError(t, err, "loading document failed: invalid character '{' looking for beginning of object key string")
	})

	t.Run("it fails on an invalid url", func(t *testing.T) {
		loader := NewEmbeddedFSDocumentLoader(testfs, nil)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("%%")
		assert.Nil(t, doc)
		assert.EqualError(t, err, "loading document failed: error parsing URL: %%")
	})

	t.Run("calls the next loader when file not found", func(t *testing.T) {
		tl := &testLoader{}
		loader := NewEmbeddedFSDocumentLoader(testfs, tl)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("unknown file")
		assert.Nil(t, doc)
		assert.True(t, tl.Called)
		assert.NoError(t, err)
	})

	t.Run("calls the next loader when the path is an url", func(t *testing.T) {
		tl := &testLoader{}
		loader := NewEmbeddedFSDocumentLoader(testfs, tl)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("https://example.com/context.jsonld")
		assert.Nil(t, doc)
		assert.True(t, tl.Called)
		assert.NoError(t, err)
	})

	t.Run("return error from the nextLoader", func(t *testing.T) {
		expectedErr := errors.New("nextloader error")
		tl := &testLoader{Err: expectedErr}
		loader := NewEmbeddedFSDocumentLoader(testfs, tl)
		assert.NotNil(t, loader)
		doc, err := loader.LoadDocument("unknown file")
		assert.Nil(t, doc)
		assert.True(t, tl.Called)
		assert.EqualError(t, err, expectedErr.Error())
	})
}
