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
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/golden_hammer/log"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var _ core.Runnable = (*GoldenHammer)(nil)
var _ core.Named = (*GoldenHammer)(nil)
var _ core.Configurable = (*GoldenHammer)(nil)
var _ core.Injectable = (*GoldenHammer)(nil)

func New(nodeDIDProvider network.NodeDIDProvider, documentOwner types.DocumentOwner, didmanAPI didman.Didman, docResolver types.DocResolver) *GoldenHammer {
	return &GoldenHammer{
		routines:        &sync.WaitGroup{},
		nodeDIDProvider: nodeDIDProvider,
		didmanAPI:       didmanAPI,
		documentOwner:   documentOwner,
		docResolver:     docResolver,
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
	nodeDIDProvider   network.NodeDIDProvider
	docResolver       types.DocResolver
	didmanAPI         didman.Didman
	documentOwner     types.DocumentOwner
	baseURLRegistered atomic.Bool
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
		h.loopFix()
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

func (h *GoldenHammer) loopFix() {
	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			err := h.registerServicesBaseURL()
			if err != nil {
				log.Logger().WithError(err).Warn("Auto-fix error")
			}
		}
	}
}

// registerServicesBaseURL registers the node's services HTTP base URL on its DIDs.
// This base URL is used to discover HTTP services (for now only OpenID4VCI wallet/issuer metadata).
// It works as follows:
// - Check if the service is registered on the node DID (if configured), if not:
//   - Try to derive the services base URL from the node's TLS certificate:
//   - For every SAN, construct potential HTTP base URLs
//   - Try to resolve the OpenID4VCI wallet metadata given the base URL
//   - If the metadata can be resolved and matches the expected identifier, register the service on the node DID.
//
// - If the node DID contains the service, try to register it on the node's care organization DID documents:
//   - Make a list of all DIDs for which the node has a private key (these can probably be managed by the node)
//   - Filter DIDs which have a NutsComm service which is equal, or resolves to, the NutsComm service of the node DID
//     (these fulfill the vendor DID - care organization DID relationship).
//   - Register a service reference on the care organization DID to the vendor DID.
func (h *GoldenHammer) registerServicesBaseURL() error {
	nodeDID := h.nodeDIDProvider.NodeDID()
	if nodeDID.Empty() {
		log.Logger().Debug("Node DID is empty, skipping fix")
		return nil
	}

	if !h.baseURLRegistered.Load() {
		err := h.registerBaseURL(nodeDID)
		if err != nil {
			return err
		}
	}

	// Now register service base URL for sub-DIDs (e.g. care organizations), if the vendor base URL is present
	if h.baseURLRegistered.Load() {
		return h.registerBaseURLForSubDIDs(nodeDID)
	}
	return nil
}

func (h *GoldenHammer) registerBaseURL(nodeDID did.DID) error {
	// DIDIdentifierResolver only looks at DID document to resolve OpenID4VCI Identifiers.
	didIDResolver := oidc4vci.DIDIdentifierResolver{ServiceResolver: didservice.NewServiceResolver(h.docResolver)}
	// TLSIdentifierResolver looks at TLS certificate to resolve OpenID4VCI Identifiers.
	tlsIDResolver := oidc4vci.NewTLSIdentifierResolver(didIDResolver, h.tlsConfig)

	// Check if the services base URL is present
	identifier, err := didIDResolver.Resolve(nodeDID)
	if err != nil {
		return fmt.Errorf("error discovering node DID OpenID4VCI identifier: %w", err)
	}
	if identifier == "" {
		// Not registered, try to resolve it using the TLS certificate
		identifier, _ = tlsIDResolver.Resolve(nodeDID) // never returns an error
		if identifier == "" {
			log.Logger().Trace("Vendor services base URL not resolvable, skipping fix")
			return nil
		}
		baseURL := identifierToBaseURL(identifier)
		if _, err := h.didmanAPI.AddEndpoint(h.ctx, nodeDID, types.BaseURLServiceType, baseURL); err != nil {
			return fmt.Errorf("unable to register vendor's node DID services base URL (url=%s): %w", baseURL.String(), err)
		}
		log.Logger().Infof("Registered vendor's node DID services base URL (url=%s)", baseURL.String())
	}
	h.baseURLRegistered.Store(true)
	return nil
}

func identifierToBaseURL(identifier string) url.URL {
	// Identifier is: baseURL + /n2n/identity/<did>
	result, _ := url.Parse(identifier[:strings.Index(identifier, "/n2n/identity/")]) // can't fail
	return *result
}

func (h *GoldenHammer) registerBaseURLForSubDIDs(nodeDID did.DID) error {
	ownedDIDs, err := h.documentOwner.ListOwned(h.ctx)
	if err != nil {
		return err
	}
	for _, currentDID := range ownedDIDs {
		// Skip it if it already has a base URL service
		existingService, err := h.findService(currentDID, types.BaseURLServiceType)
		if err != nil {
			return err
		}
		if existingService != nil {
			continue
		}

		// If it's a sub-DID of the vendor DID, register a service pointing to the vendor's
		isSubDID, err := h.isSubDIDOf(currentDID, nodeDID)
		if err != nil {
			return fmt.Errorf("unable to check if DID %s is sub-DID of node DID %s: %w", currentDID, nodeDID, err)
		}
		if isSubDID {
			ref := didservice.MakeServiceReference(nodeDID, types.BaseURLServiceType).URL
			_, err := h.didmanAPI.AddEndpoint(h.ctx, currentDID, types.BaseURLServiceType, ref)
			if err != nil {
				log.Logger().WithError(err).
					Errorf("Unable to register DID services base URL (did=%s) referring to vendor DID.", currentDID)
			} else {
				log.Logger().Infof("Registered DIDs services base URL (did=%s), referring to vendor DID.", currentDID)
			}
		}
	}
	return nil
}

// findService returns the service of the given DID and type, if present.
// If the DID is not resolvable, nil is returned. If a technical error occurs, it is returned.
func (h *GoldenHammer) findService(id did.DID, serviceType string) (*did.Service, error) {
	subjectDocument, _, err := h.docResolver.Resolve(id, nil)
	if didservice.IsFunctionalResolveError(err) {
		// Unresolvable DID document, nothing to do
		return nil, nil
	}
	if err != nil {
		// Other error occurred
		return nil, err
	}
	for _, curr := range subjectDocument.Service {
		if curr.Type == serviceType {
			return &curr, nil
		}
	}
	return nil, nil
}

// isSubDIDOf returns true if the subject DID is a sub-DID of the node DID, meaning it has a NutsComm service pointing to the node DID.
func (h *GoldenHammer) isSubDIDOf(subject did.DID, nodeDID did.DID) (bool, error) {
	if subject.String() == nodeDID.String() {
		// Would be weird
		return false, nil
	}
	// Check it has a NutsComm service that refers to the node DID
	nutsCommService, err := h.findService(subject, transport.NutsCommServiceType)
	if err != nil {
		return false, fmt.Errorf("unable to check if DID %s has NutsComm service: %w", subject, err)
	}
	if nutsCommService != nil {
		var endpoint string
		if nutsCommService.UnmarshalServiceEndpoint(&endpoint) == nil {
			// Reference has format of <did>/serviceEndpoint?type=NutsComm
			if didservice.IsServiceReference(endpoint) && strings.HasPrefix(endpoint, nodeDID.String()) {
				return true, nil
			}
		}
	}
	return false, nil
}
