/*
 * Copyright (C) 2023 Nuts community
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

package golden_hammer

import (
	"context"
	"crypto/tls"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/golden_hammer/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var _ core.Runnable = (*GoldenHammer)(nil)
var _ core.Named = (*GoldenHammer)(nil)
var _ core.Configurable = (*GoldenHammer)(nil)
var _ core.Injectable = (*GoldenHammer)(nil)

func New(vdrInstance vdr.VDR, didmanAPI didman.Didman) *GoldenHammer {
	return &GoldenHammer{
		routines:          &sync.WaitGroup{},
		vdrInstance:       vdrInstance,
		didmanAPI:         didmanAPI,
		fixedDocumentDIDs: map[string]bool{},
	}
}

// GoldenHammer is a module that fixes a node's DID configuration.
// Its name is intentionally weird, since the module should not exist.
// In future all fixes it does should be deprecated and removed after OpenID4VCI has become the standard way of exchanging VCs.
// See https://github.com/nuts-foundation/nuts-node/issues/2318
type GoldenHammer struct {
	config            Config
	ctx               context.Context
	cancelFunc        context.CancelFunc
	routines          *sync.WaitGroup
	didmanAPI         didman.Didman
	vdrInstance       vdr.VDR
	fixedDocumentDIDs map[string]bool
	tlsConfig         *tls.Config
}

func (h *GoldenHammer) Config() interface{} {
	return &h.config
}

func (h *GoldenHammer) Start() error {
	if !h.config.Enabled {
		return nil
	}

	h.ctx, h.cancelFunc = context.WithCancel(audit.Context(context.Background(), "app", vcr.ModuleName, "FixConfiguration"))
	h.routines.Add(1)
	go func() {
		defer h.routines.Done()
		h.hammerTime()
	}()
	return nil
}

func (h *GoldenHammer) Configure(config core.ServerConfig) error {
	var err error
	h.tlsConfig, _, err = config.TLS.Load()
	return err
}

func (h *GoldenHammer) Name() string {
	return "GoldenHammer"
}

func (h *GoldenHammer) Shutdown() error {
	if !h.config.Enabled {
		return nil
	}
	h.cancelFunc()
	h.routines.Wait()
	return nil
}

func (h *GoldenHammer) hammerTime() {
	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			err := h.registerServiceBaseURLs()
			if err != nil {
				log.Logger().WithError(err).Warn("Auto-fix error")
			}
		}
	}
}

// registerServiceBaseURLs registers the node's services HTTP base URL on its DIDs.
// This base URL is used to discover HTTP services (for now only OpenID4VCI wallet/issuer metadata).
//   - Make a list of owned DIDs
//   - Filter: only include documents without node-http-services-base-url service
//   - Filter: exclude documents without NutsComm service
//   - Sort: nodes with a NutsComm URL (instead of a reference) go first (so "vendor DID documents" go first).
//   - NutsComm is a service reference? Register node-http-services-base-url reference to ref'd DID document, if present there.
//   - NutsComm is a URL?
//   - Try to resolve metadata (TLSIdentifierResolver)
//   - Register resolved URL as node-http-services-base-url service
func (h *GoldenHammer) registerServiceBaseURLs() error {
	documents, err := h.listDocumentToFix()
	if err != nil {
		return err
	}
	var numFixed int
	for _, document := range documents {
		var endpointToRegister url.URL
		serviceEndpoint := getServiceEndpoint(document, transport.NutsCommServiceType)
		if resolver.IsServiceReference(serviceEndpoint) {
			// Care organization DID document, register service pointing to vendor DID.
			parentDID, err := resolver.GetDIDFromURL(serviceEndpoint)
			if err != nil {
				// Invalid NutsComm reference, skip
				log.Logger().WithError(err).
					Debugf("Invalid NutsComm reference on DID %s: %s", document.ID, serviceEndpoint)
				continue
			}
			// Only if the referenced document actually contains the service
			if !h.resolveContainsService(parentDID, resolver.BaseURLServiceType) {
				log.Logger().Debugf("Could not resolve '%s' service in referenced (NutsComm) DID document (did=%s), skipping fix for DID: %s", resolver.BaseURLServiceType, parentDID.String(), document.ID)
				continue
			}
			// All us OK
			endpointToRegister = resolver.MakeServiceReference(parentDID, resolver.BaseURLServiceType).URL
		} else {
			// Vendor DID document, register resolved identifier
			identifier, err := h.tryResolveURL(document.ID)
			if identifier == nil || err != nil {
				log.Logger().WithError(err).
					Debugf("Could not resolve vendor's services base URL for DID %s, skipping fix", document.ID)
				continue
			}
			endpointToRegister = *identifier
		}
		_, err := h.didmanAPI.AddEndpoint(h.ctx, document.ID, resolver.BaseURLServiceType, endpointToRegister)
		if err != nil {
			log.Logger().WithError(err).
				Warnf("Unable to register DID services base URL (did=%s): %s", document.ID, endpointToRegister.String())
		} else {
			numFixed++
			h.fixedDocumentDIDs[document.ID.String()] = true
		}
	}
	if numFixed > 0 {
		log.Logger().Infof("Registered base URLs on %d DIDs", numFixed)
	}
	return nil
}

func (h *GoldenHammer) listDocumentToFix() ([]did.Document, error) {
	dids, err := h.vdrInstance.DocumentOwner().ListOwned(h.ctx)
	if err != nil {
		return nil, err
	}
	var documents []did.Document
	for _, id := range dids {
		if id.Method != didnuts.MethodName {
			// Not a Nuts DID, skip
			continue
		}
		if h.fixedDocumentDIDs[id.String()] {
			// Already fixed
			continue
		}
		document, _, err := h.vdrInstance.Resolver().Resolve(id, nil)
		if err != nil {
			if !resolver.IsFunctionalResolveError(err) {
				log.Logger().WithError(err).Infof("Can't resolve DID document, skipping fix (did=%s)", id)
			}
			continue
		}
		if !containsService(*document, transport.NutsCommServiceType) {
			// Vendors and care organization DID documents have a NutsComm service,
			// others are most probably not relevant for issuing/receiving VCs (at least, they can't in their current state),
			// so we skip them.
			continue
		}
		if containsService(*document, resolver.BaseURLServiceType) {
			h.fixedDocumentDIDs[id.String()] = true
			continue
		}
		// This document needs fixing
		documents = append(documents, *document)
	}
	// Sort: since care organization DIDs refer to vendor DIDs through NutsComm service,
	// vendor DIDs should be fixed first. Meaning DIDs with NutsComm URL (instead of a reference).
	sort.SliceStable(documents, func(i, j int) bool {
		endpoint := getServiceEndpoint(documents[i], transport.NutsCommServiceType)
		return !resolver.IsServiceReference(endpoint)
	})
	return documents, nil
}

func (h *GoldenHammer) tryResolveURL(id did.DID) (*url.URL, error) {
	// TLSIdentifierResolver looks at TLS certificate to resolve OpenID4VCI Identifiers.
	tlsIDResolver := openid4vci.NewTLSIdentifierResolver(openid4vci.NoopIdentifierResolver{}, h.tlsConfig)
	identifier, err := tlsIDResolver.Resolve(id)
	if err != nil {
		return nil, err
	}
	if identifier == "" {
		return nil, nil
	}
	// Identifier is: baseURL + /n2n/identity/<did>
	return url.Parse(identifier[:strings.Index(identifier, "/n2n/identity/")])
}

// resolveContainsService returns whether 1. given DID document can be resolved, and 2. it contains the specified service.
func (h *GoldenHammer) resolveContainsService(id did.DID, serviceType string) bool {
	document, _, err := h.vdrInstance.Resolver().Resolve(id, nil)
	if resolver.IsFunctionalResolveError(err) {
		// Unresolvable DID document, nothing to do
		return false
	}
	if err != nil {
		// Other error occurred
		log.Logger().WithError(err).Infof("Can't resolve DID document, skipping fix (did=%s)", id)
		return false
	}
	return containsService(*document, serviceType)
}

func getService(document did.Document, serviceType string) *did.Service {
	for _, service := range document.Service {
		if service.Type == serviceType {
			return &service
		}
	}
	return nil
}

// getServiceEndpoint returns the endpoint of the given service as string, if present.
// If the document does not contain a service with the given type or it isn't a string, an empty string is returned.
func getServiceEndpoint(document did.Document, serviceType string) string {
	service := getService(document, serviceType)
	if service == nil {
		return ""
	}
	var endpoint string
	_ = service.UnmarshalServiceEndpoint(&endpoint)
	return endpoint
}

func containsService(document did.Document, serviceType string) bool {
	service := getService(document, serviceType)
	return service != nil
}
