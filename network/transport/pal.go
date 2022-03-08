package transport

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DecryptPAL is a helper function to decrypt an encrypted PAL header, resolving the local node's DID,
// then looking up possible decryption keys and attempting to decrypt it.
// If it can't be decrypted for whatever reason, it returns an error.
func DecryptPAL(nodeDIDResolver NodeDIDResolver, docResolver types.DocResolver, decrypter crypto.Decrypter, encryptedPAL dag.EncryptedPAL) (dag.PAL, error) {
	if len(encryptedPAL) == 0 {
		return dag.PAL{}, nil
	}

	nodeDID, err := nodeDIDResolver.Resolve()
	if err != nil {
		return nil, err
	}

	if nodeDID.Empty() {
		return nil, errors.New("node DID is not set")
	}

	didDocument, _, err := docResolver.Resolve(nodeDID, nil)
	if err != nil {
		return nil, err
	}

	keyAgreementIDs := make([]string, len(didDocument.KeyAgreement))

	for i, keyAgreement := range didDocument.KeyAgreement {
		keyAgreementIDs[i] = keyAgreement.ID.String()
	}

	return encryptedPAL.Decrypt(keyAgreementIDs, decrypter)
}
