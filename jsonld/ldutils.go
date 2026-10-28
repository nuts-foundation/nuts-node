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
	"github.com/nuts-foundation/nuts-node/v6/http/client"
	"github.com/nuts-foundation/nuts-node/v6/jsonld/log"
	"github.com/nuts-foundation/nuts-node/v6/vcr/assets"
	"github.com/piprate/json-gold/ld"
	"io/fs"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// remoteContextTimeout bounds a single fetch of a remote JSON-LD context document.
// Contexts are fetched while processing network transactions, so a server that never answers must not block that processing.
var remoteContextTimeout = 5 * time.Second

// remoteContextFailureTTL is how long a failed remote context fetch is remembered.
// During that time, loads of the same URL fail immediately with the original error instead of fetching again.
var remoteContextFailureTTL = 5 * time.Minute

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

// JWS2020ContextV1URI returns JWS2020ContextV1 as a URI
func JWS2020ContextV1URI() ssi.URI {
	return ssi.MustParseURI(Jws2020Context)
}

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
				// Remember failed remote fetches, so a dead context server costs one timeout instead of one per document
				newFailureCachingLoader(remoteContextFailureTTL,
					// Last in the chain is the defaultLoader which can resolve
					// local files and remote (via http) context documents
					ld.NewDefaultDocumentLoader(newRemoteContextHTTPClient())))))

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

// newRemoteContextHTTPClient returns the HTTP client used to fetch remote JSON-LD contexts.
// json-gold needs a *http.Client, so the node's strict HTTP client (timeout, SSRF guard, URL checks, response size limit)
// is wrapped as its transport.
func newRemoteContextHTTPClient() *http.Client {
	return &http.Client{Transport: strictClientTransport{client: client.New(remoteContextTimeout)}}
}

// strictClientTransport adapts a client.StrictHTTPClient to http.RoundTripper.
// The strict client follows redirects itself, so the outer http.Client receives the final response.
type strictClientTransport struct {
	client *client.StrictHTTPClient
}

func (s strictClientTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// RoundTrip must not modify the request, but the strict client sets the User-Agent header.
	return s.client.Do(request.Clone(request.Context()))
}

type failedLoad struct {
	err   error
	until time.Time
}

// failureCachingLoader remembers failed loads per URL for a fixed time, and returns the remembered error without
// calling the next loader during that time. Successful loads are not cached here (see ld.NewCachingDocumentLoader).
type failureCachingLoader struct {
	ttl        time.Duration
	nextLoader ld.DocumentLoader
	mutex      sync.Mutex
	failures   map[string]failedLoad
}

func newFailureCachingLoader(ttl time.Duration, nextLoader ld.DocumentLoader) *failureCachingLoader {
	return &failureCachingLoader{
		ttl:        ttl,
		nextLoader: nextLoader,
		failures:   map[string]failedLoad{},
	}
}

// LoadDocument returns the remembered error if loading u failed less than ttl ago, otherwise it calls the next loader.
func (f *failureCachingLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if err := f.recentFailure(u); err != nil {
		log.Logger().Debugf("Not fetching JSON-LD context, it failed recently (url=%s)", u)
		return nil, err
	}
	document, err := f.nextLoader.LoadDocument(u)
	if err != nil {
		f.recordFailure(u, err)
		log.Logger().WithError(err).Warnf("Failed to load JSON-LD context, not retrying for %s (url=%s)", f.ttl, u)
	}
	return document, err
}

func (f *failureCachingLoader) recentFailure(u string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	failure, ok := f.failures[u]
	if !ok {
		return nil
	}
	if time.Now().After(failure.until) {
		delete(f.failures, u)
		return nil
	}
	return failure.err
}

func (f *failureCachingLoader) recordFailure(u string, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	now := time.Now()
	// Prune expired entries, so the map stays bounded by the number of URLs that failed within the last ttl.
	for failedURL, failure := range f.failures {
		if now.After(failure.until) {
			delete(f.failures, failedURL)
		}
	}
	f.failures[u] = failedLoad{err: err, until: now.Add(f.ttl)}
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
