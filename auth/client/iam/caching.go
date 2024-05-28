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

package iam

import (
	"bytes"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/pquerna/cachecontrol"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// CachingHTTPRequestDoer is a cache for HTTP responses for DID/OAuth2/OpenID clients.
// It only caches GET requests (since generally only metadata is cacheable), and only if the response is cacheable.
// It only works on expiration time and does not respect ETags headers.
type CachingHTTPRequestDoer struct {
	maxBytes    int
	requestDoer core.HTTPRequestDoer

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

func (h *CachingHTTPRequestDoer) Do(httpRequest *http.Request) (*http.Response, error) {
	if httpRequest.Method == http.MethodGet {
		if response := h.getCachedEntry(httpRequest); response != nil {
			return response, nil
		}
	}

	httpResponse, err := h.requestDoer.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	if httpRequest.Method == http.MethodGet {
		reasons, expirationTime, err := cachecontrol.CachableResponse(httpRequest, httpResponse, cachecontrol.Options{PrivateCache: false})
		if err != nil {
			log.Logger().WithError(err).Infof("error while checking cacheability of response (url=%s), not caching", httpRequest.URL.String())
			return httpResponse, nil
		}
		// We don't want to cache responses for too long, as that increases the risk of staleness,
		// and could keep cause very long-lived entries to never be pruned.
		maxExpirationTime := time.Now().Add(time.Hour)
		if expirationTime.After(maxExpirationTime) {
			expirationTime = maxExpirationTime
		}
		if len(reasons) > 0 || expirationTime.IsZero() {
			log.Logger().Debugf("response (url=%s) is not cacheable: %v", httpRequest.URL.String(), reasons)
			return httpResponse, nil
		}
		responseBytes, err := io.ReadAll(httpResponse.Body)
		if err != nil {
			return nil, fmt.Errorf("error while reading response body for caching: %w", err)
		}
		h.mux.Lock()
		defer h.mux.Unlock()
		if len(responseBytes) <= h.maxBytes { // sanity check
			h.insert(&cacheEntry{
				responseData:    responseBytes,
				requestMethod:   httpRequest.Method,
				requestURL:      httpRequest.URL,
				requestRawQuery: httpRequest.URL.RawQuery,
				responseStatus:  httpResponse.StatusCode,
				responseHeaders: httpResponse.Header,
				expirationTime:  expirationTime,
			})
		}
		httpResponse.Body = io.NopCloser(bytes.NewReader(responseBytes))
	}
	return httpResponse, nil
}

func (h *CachingHTTPRequestDoer) getCachedEntry(httpRequest *http.Request) *http.Response {
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

func (h *CachingHTTPRequestDoer) removeExpiredEntries() {
	var current = h.head
	for current != nil {
		if current.expirationTime.Before(time.Now()) {
			current = h.pop()
		} else {
			break
		}
	}
}

// insert adds a new entry to the cache.
func (h *CachingHTTPRequestDoer) insert(entry *cacheEntry) {
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

// pop removes the first entry from the linked list
func (h *CachingHTTPRequestDoer) pop() *cacheEntry {
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

func cacheHTTPResponses(requestDoer core.HTTPRequestDoer) *CachingHTTPRequestDoer {
	return &CachingHTTPRequestDoer{
		maxBytes:     10 * 1024 * 1024,
		requestDoer:  requestDoer,
		entriesByURL: map[string][]*cacheEntry{},
		mux:          sync.RWMutex{},
	}
}
