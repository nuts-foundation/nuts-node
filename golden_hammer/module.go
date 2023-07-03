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
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
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

func New(documentOwner types.DocumentOwner, didmanAPI didman.Didman, docResolver types.DocResolver) *GoldenHammer {
	return &GoldenHammer{
		routines:          &sync.WaitGroup{},
		didmanAPI:         didmanAPI,
		documentOwner:     documentOwner,
		docResolver:       docResolver,
		fixedDocumentDIDs: map[string]bool{},
	}
}

// GoldenHammer is a module that fixes a node's DID configuration.
// Its name is intentionally weird, since the module should not exist.
// In future all fixes it does should be deprecated and removed after they've become obsolete.
type GoldenHammer struct {
	config            Config
	ctx               context.Context
	cancelFunc        context.CancelFunc
	routines          *sync.WaitGroup
	docResolver       types.DocResolver
	didmanAPI         didman.Didman
	documentOwner     types.DocumentOwner
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
//   - Filter documents without node-http-services-base-url service
//   - Sort: nodes without NutsComm service go first (so "vendor DID documents" go first).
//   - Try to resolve metadata (TLSIdentifierResolver), if successful, continue
//   - No NutsComm service reference? Register node-http-services-base-url service it on the DID document itself.
//   - Has NutsComm service reference? Register node-http-services-base-url reference to ref'd DID document, if present there.
func (h *GoldenHammer) registerServiceBaseURLs() error {
	documents, err := h.listDocumentToFix()
	if err != nil {
		return err
	}
	for _, document := range documents {
		var endpointToRegister url.URL
		serviceEndpoint := getServiceEndpoint(document, transport.NutsCommServiceType)
		if didservice.IsServiceReference(serviceEndpoint) {
			// Care organization DID document, register service pointing to vendor DID.
			parentDID, err := didservice.GetDIDFromURL(serviceEndpoint)
			if err != nil {
				// Invalid NutsComm reference, skip
				log.Logger().WithError(err).
					Debugf("Invalid NutsComm reference on DID %s: %s", document.ID, serviceEndpoint)
				continue
			}
			// Only if the referenced document actually contains the service
			if h.resolveContainsService(parentDID, types.BaseURLServiceType) {
				log.Logger().Debugf("Could not resolve '%s' service in referenced (NutsComm) DID document (did=%s), skipping fix for DID: %s", types.BaseURLServiceType, parentDID.String(), document.ID)
				continue
			}
			// All us OK
			endpointToRegister = didservice.MakeServiceReference(parentDID, types.BaseURLServiceType).URL
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
		_, err := h.didmanAPI.AddEndpoint(h.ctx, document.ID, types.BaseURLServiceType, endpointToRegister)
		if err != nil {
			log.Logger().WithError(err).
				Errorf("Unable to register DID services base URL (did=%s): %s", document.ID, endpointToRegister.String())
		} else {
			h.fixedDocumentDIDs[document.ID.String()] = true
			log.Logger().Infof("Registered DIDs services base URL (did=%s): %s", document.ID, endpointToRegister.String())
		}
	}
	return nil
}

func (h *GoldenHammer) listDocumentToFix() ([]did.Document, error) {
	dids, err := h.documentOwner.ListOwned(h.ctx)
	if err != nil {
		return nil, err
	}
	var documents []did.Document
	for _, id := range dids {
		if h.fixedDocumentDIDs[id.String()] {
			// Already fixed
			continue
		}
		document, _, err := h.docResolver.Resolve(id, nil)
		if err != nil {
			if !didservice.IsFunctionalResolveError(err) {
				log.Logger().WithError(err).Infof("Can't resolve DID document, skipping fix (did=%s)", id)
			}
			continue
		}
		if containsService(*document, types.BaseURLServiceType) {
			h.fixedDocumentDIDs[id.String()] = true
			continue
		}
		// This document needs fixing
		documents = append(documents, *document)
	}
	// Sort: since care organization DIDs refer to vendor DIDs through NutsComm service,
	// vendor DIDs should be fixed first. Meaning DIDs without NutsComm service should go first.
	sort.Slice(documents, func(i, j int) bool {
		return containsService(documents[i], transport.NutsCommServiceType)
	})
	return documents, nil
}

func (h *GoldenHammer) tryResolveURL(id did.DID) (*url.URL, error) {
	// DIDIdentifierResolver only looks at DID document to resolve OpenID4VCI Identifiers.
	didIDResolver := oidc4vci.DIDIdentifierResolver{ServiceResolver: didservice.NewServiceResolver(h.docResolver)}
	// TLSIdentifierResolver looks at TLS certificate to resolve OpenID4VCI Identifiers.
	tlsIDResolver := oidc4vci.NewTLSIdentifierResolver(didIDResolver, h.tlsConfig)

	// Check if the services base URL is present
	identifier, err := didIDResolver.Resolve(id)
	if err != nil {
		return nil, err
	}
	if identifier == "" {
		// Not registered, try to resolve it using the TLS certificate
		identifier, err = tlsIDResolver.Resolve(id)
		if err != nil {
			return nil, err
		}
		if identifier == "" {
			return nil, nil
		}
	}
	// Identifier is: baseURL + /n2n/identity/<did>
	return url.Parse(identifier[:strings.Index(identifier, "/n2n/identity/")])
}

// resolveContainsService returns whether 1. given DID document can be resolved, and 2. it contains the specified service.
func (h *GoldenHammer) resolveContainsService(id did.DID, serviceType string) bool {
	document, _, err := h.docResolver.Resolve(id, nil)
	if didservice.IsFunctionalResolveError(err) {
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
