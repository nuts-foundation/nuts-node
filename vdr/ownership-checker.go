package vdr

import (
	"github.com/nuts-foundation/go-did/did"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

type OwnershipChecker struct {
	KeyResolver KeyResolver
	KeyChecker  crypto.PrivateKeyChecker
}

func (c OwnershipChecker) OwnedByThisNode(id did.DID) (error) {
	key, err := c.KeyResolver.ResolveAssertionKeyID(id)
	if err != nil {
		return err
	}

	if !c.KeyChecker.PrivateKeyExists(key.String()) {
		return types.ErrDIDNotManagedByThisNode
	}
	return nil
}
