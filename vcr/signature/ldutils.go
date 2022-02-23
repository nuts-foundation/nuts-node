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

package signature

import (
	"embed"
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/piprate/json-gold/ld"
	"net/url"
)

// embeddedFSDocumentLoader tries to load documents from an embedded filesystem.
type embeddedFSDocumentLoader struct {
	fs         embed.FS
	nextLoader ld.DocumentLoader
}

// NewEmbeddedFSDocumentLoader creates a new embeddedFSDocumentLoader for an embedded filesystem.
func NewEmbeddedFSDocumentLoader(fs embed.FS, nextLoader ld.DocumentLoader) ld.DocumentLoader {
	return &embeddedFSDocumentLoader{
		fs:         fs,
		nextLoader: nextLoader,
	}
}

// LoadDocument tries to load the document from the embedded filesystem.
// If the document is not a file or could not be found it tries the nextLoader.
func (e embeddedFSDocumentLoader) LoadDocument(path string) (*ld.RemoteDocument, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", path))
	}

	protocol := parsedURL.Scheme
	if protocol != "http" && protocol != "https" {
		remoteDoc := &ld.RemoteDocument{}
		remoteDoc.DocumentURL = path
		file, err := e.fs.Open(path)
		if err != nil {
			return e.nextLoader.LoadDocument(path)
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

// NewContextLoader creates a new JSON-LD context loader with the embedded FS as first loader.
// It loads the most used context from the embedded FS. This ensures the contents cannot be altered.
// If allowExternalCalls is set to true, it also loads external context from the internet.
func NewContextLoader(allowExternalCalls bool) (ld.DocumentLoader, error) {
	var nextLoader ld.DocumentLoader
	if allowExternalCalls {
		nextLoader = ld.NewDefaultDocumentLoader(nil)
	}
	loader := ld.NewCachingDocumentLoader(NewEmbeddedFSDocumentLoader(assets.Assets, nextLoader))
	if err := loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
		"https://schema.org":                                                 "assets/contexts/schema-org-v13.ldjson",
	}); err != nil {
		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
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

	for key, _ := range uniqueMap {
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
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}
	return
}
