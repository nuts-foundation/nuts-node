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

package jsonld

import (
	"embed"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed test/*
var testfs embed.FS

type testLoader struct {
	Called     bool
	CalledWith string
	Err        error
}

func (t *testLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	t.Called = true
	t.CalledWith = u
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

func TestNewContextLoader(t *testing.T) {
	t.Run("loads local file", func(t *testing.T) {
		cfg := DefaultContextConfig()
		cfg.LocalFileMapping = map[string]string{
			"http://test-context.com": "./test/test.jsonld",
		}
		_, err := NewContextLoader(true, cfg)
		assert.NoError(t, err)
	})

	t.Run("loads local file (external calls disallowed)", func(t *testing.T) {
		cfg := DefaultContextConfig()
		cfg.LocalFileMapping = map[string]string{
			"http://test-context.com": "./test/test.jsonld",
		}
		_, err := NewContextLoader(false, cfg)
		assert.NoError(t, err)
	})

	t.Run("errors when local file is not found", func(t *testing.T) {
		cfg := DefaultContextConfig()
		cfg.LocalFileMapping = map[string]string{
			"http://test-context.com": "test/non-existing.jsonld",
		}
		_, err := NewContextLoader(true, cfg)
		assert.EqualError(t, err, "preloading context http://test-context.com failed: loading document failed: open test/non-existing.jsonld: no such file or directory")
	})

	t.Run("it creates a new contextLoader", func(t *testing.T) {
		loader, err := NewContextLoader(false, DefaultContextConfig())
		assert.NoError(t, err)
		doc, err := loader.LoadDocument("https://schema.org")
		assert.NoError(t, err)
		assert.Equal(t, "assets/contexts/schema-org-v13.ldjson", doc.DocumentURL)
	})

	t.Run("it fails requesting an external doc when allowingExternalCalls is false", func(t *testing.T) {
		loader, err := NewContextLoader(false, DefaultContextConfig())
		assert.NoError(t, err)
		_, err = loader.LoadDocument("http://example.org")
		assert.EqualError(t, err, "loading document failed: context not on the remoteallowlist: http://example.org")
	})

	t.Run("it resolves an external doc when allowingExternalCalls is true", func(t *testing.T) {
		loader, err := NewContextLoader(true, DefaultContextConfig())
		assert.NoError(t, err)
		doc, err := loader.LoadDocument("http://schema.org")
		assert.NoError(t, err)
		assert.Equal(t, "https://schema.org/docs/jsonldcontext.jsonld", doc.DocumentURL)
	})
}

func TestAddContext(t *testing.T) {
	t.Run("it adds a context to an empty document", func(t *testing.T) {
		doc := map[string]interface{}{}
		newContext := ssi.MustParseURI("http://nuts.nl")
		doc["@context"] = AddContext(doc["@context"], newContext)

		assert.Len(t, doc["@context"], 1)
		assert.Equal(t, doc["@context"].([]interface{})[0], newContext.String())
	})

	t.Run("it adds a context to a single string context", func(t *testing.T) {
		doc := map[string]interface{}{}
		doc["@context"] = "http://example.org"
		newContext := ssi.MustParseURI("http://nuts.nl")
		doc["@context"] = AddContext(doc["@context"], newContext)

		assert.Len(t, doc["@context"], 2)
		assert.Contains(t, doc["@context"].([]interface{}), newContext.String())
		assert.Contains(t, doc["@context"].([]interface{}), "http://example.org")
	})

	t.Run("it has support for embedded contexts", func(t *testing.T) {
		doc := map[string]interface{}{}
		doc["@context"] = map[string]interface{}{
			"title": "http://schema.org#title",
		}
		newContext := ssi.MustParseURI("http://nuts.nl")
		doc["@context"] = AddContext(doc["@context"], newContext)

		assert.Len(t, doc["@context"], 2)
		assert.Contains(t, doc["@context"].([]interface{}), newContext.String())
		assert.Contains(t, doc["@context"].([]interface{})[0], "title")
	})

	t.Run("it removes duplicates", func(t *testing.T) {
		doc := map[string]interface{}{}
		newContext := ssi.MustParseURI("http://nuts.nl")
		doc["@context"] = AddContext(doc["@context"], newContext)
		doc["@context"] = AddContext(doc["@context"], newContext)

		assert.Len(t, doc["@context"], 1)
		assert.Equal(t, doc["@context"].([]interface{})[0], newContext.String())
	})
}

func TestMappedDocumentLoader_LoadDocument(t *testing.T) {
	t.Run("it maps", func(t *testing.T) {
		tl := &testLoader{}
		loader := NewMappedDocumentLoader(map[string]string{"foo": "bar"}, tl)
		_, err := loader.LoadDocument("foo")
		assert.NoError(t, err)
		assert.True(t, tl.Called)
		assert.Equal(t, tl.CalledWith, "bar")
	})

	t.Run("it passes thru unmapped urls", func(t *testing.T) {
		tl := &testLoader{}
		loader := NewMappedDocumentLoader(map[string]string{"foo": "bar"}, tl)
		_, err := loader.LoadDocument("fnorp")
		assert.NoError(t, err)
		assert.True(t, tl.Called)
		assert.Equal(t, tl.CalledWith, "fnorp")
	})
}

func Test_filteredDocumentLoader(t *testing.T) {

	t.Run("create a new filteredDocumentLoader", func(t *testing.T) {
		loader := NewFilteredLoader([]string{}, &testLoader{})
		assert.Implements(t, (*ld.DocumentLoader)(nil), loader)
	})

	t.Run("it passes through an allowed url", func(t *testing.T) {
		mockLoader := &testLoader{}
		sut := NewFilteredLoader([]string{"foo.com"}, mockLoader)

		_, err := sut.LoadDocument("foo.com")
		assert.NoError(t, err)
		assert.True(t, mockLoader.Called)
		assert.Equal(t, "foo.com", mockLoader.CalledWith)
	})

	t.Run("it blocks urls not on the list", func(t *testing.T) {
		mockLoader := &testLoader{}
		sut := NewFilteredLoader([]string{"foo.com"}, mockLoader)

		_, err := sut.LoadDocument("not-allowed.com")
		assert.EqualError(t, err, "loading document failed: context not on the remoteallowlist: not-allowed.com")
		assert.False(t, mockLoader.Called)
	})
}
