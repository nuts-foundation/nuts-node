package oidc4vci_v0

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
)

// TODO: Split this file into multiple files, per role (issuer/holder)

var _ StrictServerInterface = (*Wrapper)(nil)

type Wrapper struct {
	VCR vcr.VCR
}

func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, nil))
}
