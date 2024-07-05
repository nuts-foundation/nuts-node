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
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/jsonld/log"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/piprate/json-gold/ld"
	"io/fs"
	"net/url"
)

// ContextsConfig contains config for json-ld document loader
type ContextsConfig struct {
	// RemoteAllowList A list with urls as string which are allowed to request
	RemoteAllowList []string `koanf:"remoteallowlist"`
	// LocalFileMapping contains a list of context URLs mapped to a local file
	LocalFileMapping map[string]string `koanf:"localmapping"`
}

var ContextURLNotAllowedErr = errors.New("context not on the remoteallowlist")

// embeddedFSDocumentLoader tries to load documents from an embedded filesystem.
type embeddedFSDocumentLoader struct {
	fs         embed.FS
	nextLoader ld.DocumentLoader
}

// filteredDocumentLoader is a ld.DocumentLoader which contains a list of allowed URLs.
// the nextLoader will only be called when the URL is on the AllowedURLs list.
type filteredDocumentLoader struct {
	AllowedURLs []string
	nextLoader  ld.DocumentLoader
}

// NewEmbeddedFSDocumentLoader creates a new embeddedFSDocumentLoader for an embedded filesystem.
func NewEmbeddedFSDocumentLoader(fs embed.FS, nextLoader ld.DocumentLoader) ld.DocumentLoader {
	return &embeddedFSDocumentLoader{
		fs:         fs,
		nextLoader: nextLoader,
	}
}

// NewFilteredLoader accepts a list of allowed urls and a nextLoader and creates a new filteredDocumentLoader
func NewFilteredLoader(allowedURLs []string, nextLoader ld.DocumentLoader) ld.DocumentLoader {
	return &filteredDocumentLoader{AllowedURLs: allowedURLs, nextLoader: nextLoader}
}

// LoadDocument calls the nextLoader if the URL u is on the AllowedURLs list, returns a ld.LoadingDocumentFailed otherwise.
func (h filteredDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	for _, allowedURL := range h.AllowedURLs {
		if allowedURL == u {
			return h.nextLoader.LoadDocument(u)
		}
	}
	return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, ContextURLNotAllowedErr)
}

type mappedDocumentLoader struct {
	mapping    map[string]string
	nextLoader ld.DocumentLoader
}

// NewMappedDocumentLoader rewrites document request using a mapping and calls the nextLoader
func NewMappedDocumentLoader(mapping map[string]string, nextLoader ld.DocumentLoader) ld.DocumentLoader {
	return &mappedDocumentLoader{
		mapping:    mapping,
		nextLoader: nextLoader,
	}
}

// LoadDocument rewrites u according to the mapping and calls the next loader.
// If u is not found in the mapping, just call the nextLoader with u.
func (m mappedDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	mappedU, ok := m.mapping[u]
	if ok {
		log.Logger().Tracef("Loading context %s from %s", u, mappedU)
		return m.nextLoader.LoadDocument(mappedU)
	}
	return m.nextLoader.LoadDocument(u)
}

// LoadDocument tries to load the document from the embedded filesystem.
// If the document is not a file or could not be found it tries the nextLoader.
func (e embeddedFSDocumentLoader) LoadDocument(path string) (*ld.RemoteDocument, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", path))
	}

	protocol := parsedURL.Scheme
	// ignore http(s) documents
	if protocol != "http" && protocol != "https" {
		remoteDoc := &ld.RemoteDocument{}
		remoteDoc.DocumentURL = path
		// If fileNotExists, pass on to the nextLoader
		file, err := e.fs.Open(path)
		if errors.Is(err, fs.ErrNotExist) {
			if e.nextLoader != nil {
				return e.nextLoader.LoadDocument(path)
			}
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		log.Logger().Tracef("Loading %s from embedded filesystem", path)
		// If an error occurred, fail
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err.Error())
		}
		// If the file points to a directory, fail
		stat, _ := file.Stat()
		if stat.IsDir() {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, errors.New("document can not be a directory"))
		}
		defer file.Close()
		remoteDoc.Document, err = ld.DocumentFromReader(file)
		if err != nil {
			return nil, err
		}
		return remoteDoc, nil
	}
	if e.nextLoader != nil {
		return e.nextLoader.LoadDocument(path)
	}
	return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, nil)
}

// SchemaOrgContext contains the schema.org context url
const SchemaOrgContext = "https://schema.org"

// W3cVcContext contains the w3c VerifiableCredential type context
const W3cVcContext = "https://www.w3.org/2018/credentials/v1"

// W3cStatusList2021Context contains the StatusList2021 related context
const W3cStatusList2021Context = "https://w3id.org/vc/status-list/2021/v1"

// Jws2020Context contains the JsonWebToken2020 Proof type context
const Jws2020Context = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"

// DefaultContextConfig returns the default list of allowed external resources and a mapping to embedded contexts
func DefaultContextConfig() ContextsConfig {
	return ContextsConfig{
		RemoteAllowList: DefaultAllowList(),
		LocalFileMapping: map[string]string{
			"https://nuts.nl/credentials/v1":   "assets/contexts/nuts.ldjson",
			"https://nuts.nl/credentials/2024": "assets/contexts/nuts-2024.ldjson",
			W3cVcContext:                       "assets/contexts/w3c-credentials-v1.ldjson",
			W3cStatusList2021Context:           "assets/contexts/w3c-statuslist2021.ldjson",
			Jws2020Context:                     "assets/contexts/lds-jws2020-v1.ldjson",
			SchemaOrgContext:                   "assets/contexts/schema-org-v13.ldjson",
		},
	}
}

// DefaultAllowList returns the default allow list for external contexts
func DefaultAllowList() []string {
	return []string{SchemaOrgContext, W3cVcContext, Jws2020Context, W3cStatusList2021Context}
}

// NewContextLoader creates a new JSON-LD context loader with the embedded FS as first loader.
// It loads the most used context from the embedded FS. This ensures the contents cannot be altered.
// If allowExternalCalls is set to true, it also loads external context from the internet.
func NewContextLoader(allowUnlistedExternalCalls bool, contexts ContextsConfig) (ld.DocumentLoader, error) {
	// Build the documentLoader chain:
	// Start with rewriting all context urls to their mapped counterparts
	loader := NewMappedDocumentLoader(contexts.LocalFileMapping,
		// Cache all the documents
		ld.NewCachingDocumentLoader(
			// Handle all embedded file system files
			NewEmbeddedFSDocumentLoader(assets.Assets,
				// Last in the chain is the defaultLoader which can resolve
				// local files and remote (via http) context documents
				ld.NewDefaultDocumentLoader(nil))))

	// If unlisted calls are not allowed, filter all calls to the defaultLoader
	if !allowUnlistedExternalCalls {
		// only allow explicitly allowed remote urls and listed local files:
		allowed := make([]string, len(contexts.RemoteAllowList), len(contexts.RemoteAllowList)+len(contexts.LocalFileMapping))
		copy(allowed, contexts.RemoteAllowList)
		for url := range contexts.LocalFileMapping {
			allowed = append(allowed, url)
		}
		loader = NewFilteredLoader(allowed, loader)
	}

	for contextURL, localFile := range contexts.LocalFileMapping {
		// preload mapped files:
		if _, err := loader.LoadDocument(contextURL); err != nil {
			return nil, fmt.Errorf("preloading context %s failed: %w", contextURL, err)
		}
		log.Logger().Debugf("Loaded context from local file (context=%s, file=%s)", contextURL, localFile)
	}

	return loader, nil
}

// LDUtil package a set of often used JSON-LD operations for re-usability.
type LDUtil struct {
	LDDocumentLoader ld.DocumentLoader
}

// AddContext adds the context to the @context array. It makes sure no duplicates will exist.
func AddContext(context interface{}, newContext ssi.URI) []interface{} {
	if context == nil {
		context = []string{}
	}
	var contexts []interface{}

	switch c := context.(type) {
	case string: // if the context is a single string
		contexts = append(contexts, c)
	case []interface{}: // if the contexts are a list
		contexts = append(contexts, c...)
	case map[string]interface{}: // support for embedded context
		contexts = append(contexts, c)
	}

	contexts = append(contexts, newContext.String())

	var results []interface{}

	// Deduplicate the string values
	uniqueMap := make(map[interface{}]interface{})
	for _, val := range contexts {
		switch v := val.(type) {
		case string:
			uniqueMap[val] = true
		case map[string]interface{}: // embedded context
			// this cannot be easily hashed and so not deduplicated
			results = append(results, v)
		}
	}

	for key := range uniqueMap {
		results = append(results, key)
	}

	return results
}

// Canonicalize canonicalizes the json-ld input according to the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm.
func (util LDUtil) Canonicalize(input interface{}) (result interface{}, err error) {
	var optionsMap map[string]interface{}
	inputAsJSON, _ := json.Marshal(input)
	if err := json.Unmarshal(inputAsJSON, &optionsMap); err != nil {
		return nil, err
	}
	proc := ld.NewJsonLdProcessor()

	normalizeOptions := ld.NewJsonLdOptions("")
	normalizeOptions.DocumentLoader = util.LDDocumentLoader
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	result, err = proc.Normalize(optionsMap, normalizeOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize the json-ld document: %w", err)
	}
	return
}
