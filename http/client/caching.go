/*
 * Copyright (C) 2024 Nuts community
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

package client

import (
	"bytes"
	"fmt"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/pquerna/cachecontrol"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultCachingTransport is a http.RoundTripper that can be used as a default transport for HTTP clients.
// If caching is enabled, it will cache responses according to RFC 7234.
// If caching is disabled, it will behave like http.DefaultTransport.
var DefaultCachingTransport = http.DefaultTransport

// maxCacheTime is the maximum time responses are cached.
// Even if the server responds with a longer cache time, responses are never cached longer than maxCacheTime.
const maxCacheTime = time.Hour

var _ http.RoundTripper = &CachingRoundTripper{}

// NewCachingTransport creates a new CachingHTTPTransport with the given underlying transport and cache size.
func NewCachingTransport(underlyingTransport http.RoundTripper, responsesCacheSize int) *CachingRoundTripper {
	return &CachingRoundTripper{
		cache:            newCache(responsesCacheSize),
		wrappedTransport: underlyingTransport,
	}
}

// CachingRoundTripper is a simple HTTP client cache for HTTP responses.
// It only caches GET requests (since for POST request caching, request bodies need to be cached as well),
// and only if the response is cacheable according to RFC 7234.
// It only works on expiration time and does not respect ETags headers.
// When the cache is full, the entries that expire first are removed to make room for new entries (since those are the first ones to be pruned any ways).
type CachingRoundTripper struct {
	cache            *responseCache
	wrappedTransport http.RoundTripper
}

func (r *CachingRoundTripper) RoundTrip(httpRequest *http.Request) (*http.Response, error) {
	if httpRequest.Method == http.MethodGet {
		if response := r.cache.get(httpRequest); response != nil {
			return response, nil
		}
	}
	httpResponse, err := r.wrappedTransport.RoundTrip(httpRequest)
	if err != nil {
		return nil, err
	}
	err = r.cacheResponse(httpRequest, httpResponse)
	if err != nil {
		return nil, err
	}
	return httpResponse, nil
}

// cacheResponse caches the response if it's cacheable.
func (r *CachingRoundTripper) cacheResponse(httpRequest *http.Request, httpResponse *http.Response) error {
	if httpRequest.Method != http.MethodGet {
		return nil
	}
	reasons, expirationTime, err := cachecontrol.CachableResponse(httpRequest, httpResponse, cachecontrol.Options{PrivateCache: false})
	if err != nil {
		log.Logger().WithError(err).Infof("error while checking cacheability of response (url=%s), not caching", httpRequest.URL.String())
		return nil
	}
	// We don't want to cache responses for too long, as that increases the risk of staleness,
	// and could keep cause very long-lived entries to never be pruned.
	maxExpirationTime := time.Now().Add(maxCacheTime)
	if expirationTime.After(maxExpirationTime) {
		expirationTime = maxExpirationTime
	}
	if len(reasons) > 0 || expirationTime.IsZero() {
		log.Logger().Debugf("response (url=%s) is not cacheable: %v", httpRequest.URL.String(), reasons)
		return nil
	}
	responseBytes, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("error while reading response body for caching: %w", err)
	}
	r.cache.insert(&cacheEntry{
		responseData:    responseBytes,
		requestMethod:   httpRequest.Method,
		requestURL:      httpRequest.URL,
		requestRawQuery: httpRequest.URL.RawQuery,
		responseStatus:  httpResponse.StatusCode,
		responseHeaders: httpResponse.Header,
		expirationTime:  expirationTime,
	})
	httpResponse.Body = io.NopCloser(bytes.NewReader(responseBytes))
	return nil
}

func newCache(responsesCacheSize int) *responseCache {
	return &responseCache{
		maxBytes:     responsesCacheSize,
		entriesByURL: map[string][]*cacheEntry{},
		mux:          sync.RWMutex{},
	}
}

type responseCache struct {
	maxBytes int
	// currentSizeBytes is the current size of the cache in bytes.
	// It's used to make room for new entries when the cache is full.
	currentSizeBytes int
	// head is the first entry of a linked list of cache entries, ordered by expiration time.
	// The first entry is the one that will expire first, which optimizes the removal of expired entries.
	// When an entry is inserted in the cache, it's inserted in the right place in the linked list (ordered by expiry).
	head *cacheEntry
	// entriesByURL is a map of cache entries, indexed by the URL of the request.
	// This optimizes the lookup of cache entries by URL.
	entriesByURL map[string][]*cacheEntry
	mux          sync.RWMutex
}

type cacheEntry struct {
	responseData    []byte
	requestURL      *url.URL
	requestMethod   string
	requestRawQuery string
	expirationTime  time.Time
	next            *cacheEntry
	responseStatus  int
	responseHeaders http.Header
}

// get is called by the transport to get a cached response.
func (h *responseCache) get(httpRequest *http.Request) *http.Response {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.removeExpiredEntries()
	// Find cached response
	entries := h.entriesByURL[httpRequest.URL.String()]
	for _, entry := range entries {
		if entry.requestMethod == httpRequest.Method && entry.requestRawQuery == httpRequest.URL.RawQuery {
			return &http.Response{
				StatusCode: entry.responseStatus,
				Header:     entry.responseHeaders,
				Body:       io.NopCloser(bytes.NewReader(entry.responseData)),
			}
		}
	}
	return nil
}

// insert is called by the transport to insert a new entry to the cache.
func (h *responseCache) insert(entry *cacheEntry) {
	if len(entry.responseData) > h.maxBytes { // sanity check: don't cache responses that are larger than the cache
		return
	}
	h.mux.Lock()
	defer h.mux.Unlock()
	// See if we need to make room for the new entry
	for h.currentSizeBytes+len(entry.responseData) >= h.maxBytes {
		_ = h.pop()
	}
	if h.head == nil {
		// First entry
		h.head = entry
	} else {
		// Insert in the linked list, ordered by expiration time
		var current = h.head
		for current.next != nil && current.next.expirationTime.Before(entry.expirationTime) {
			current = current.next
		}
		if current == h.head {
			h.head = entry
		}
		entry.next = current.next
		current.next = entry
	}
	// Insert in the URL map for quick lookup
	h.entriesByURL[entry.requestURL.String()] = append(h.entriesByURL[entry.requestURL.String()], entry)

	h.currentSizeBytes += len(entry.responseData)
}

// removeExpiredEntries removes all entries that have expired. Do not call it directly.
func (h *responseCache) removeExpiredEntries() {
	var current = h.head
	for current != nil {
		if current.expirationTime.Before(time.Now()) {
			current = h.pop()
		} else {
			break
		}
	}
}

// pop removes the first entry from the linked list. Do not call it directly.
func (h *responseCache) pop() *cacheEntry {
	if h.head == nil {
		return nil
	}
	requestURL := h.head.requestURL.String()
	entries := h.entriesByURL[requestURL]
	for i, entry := range entries {
		if entry == h.head {
			h.entriesByURL[requestURL] = append(entries[:i], entries[i+1:]...)
			if len(h.entriesByURL[requestURL]) == 0 {
				delete(h.entriesByURL, requestURL)
			}
			break
		}
	}
	h.currentSizeBytes -= len(h.head.responseData)
	h.head = h.head.next
	return h.head
}
