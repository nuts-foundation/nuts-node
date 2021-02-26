package vdr

import (
	"fmt"
	"github.com/nuts-foundation/go-did"
	"hash/crc32"
)

// NameResolver defines functions for resolving the name of an entity holding a DID.
type NameResolver interface {
	// Resolve resolves the name of a DID holder.
	Resolve(input did.DID) (string, error)
}

// NewDummyNameResolver returns a NameResolver that generates a name based on the DID.
// TODO: Remove this after implementing VCs (https://github.com/nuts-foundation/nuts-node/issues/90)
func NewDummyNameResolver() NameResolver {
	return &dummyNameResolver{}
}

type dummyNameResolver struct {
}

func (d dummyNameResolver) Resolve(input did.DID) (string, error) {
	return fmt.Sprintf("Company #%d", crc32.ChecksumIEEE([]byte(input.String()))%1000), nil
}
