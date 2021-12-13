package dag

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
)

func EncryptPal(keyResolver types.KeyResolver, participantsAddrs []did.DID) ([][]byte, error) {
	var encryptionKeys []*ecdsa.PublicKey
	var recipientStrs []string
	for _, recipient := range participantsAddrs {
		recipientStrs = append(recipientStrs, recipient.String())
		rawKak, err := keyResolver.ResolveKeyAgreementKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve keyAgreement key (recipient=%s): %w", recipient, err)
		}
		kak, ok := rawKak.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("resolved keyAgreement key is not an elliptic curve key (recipient=%s)", recipient)
		}
		encryptionKeys = append(encryptionKeys, kak)
	}
	plaintext := []byte(strings.Join(recipientStrs, "\n"))

	// Encrypt plaintext with each KAK
	var cipherTexts [][]byte
	for _, key := range encryptionKeys {
		cipherText, err := crypto.EciesEncrypt(key, plaintext)
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt 'pal' header: %w", err)
		}
		cipherTexts = append(cipherTexts, cipherText)
	}

	return cipherTexts, nil
}

func DecryptPal(pal [][]byte, keyAgreementKIDs []string, decryptor crypto.Decryptor) ([]did.DID, error) {
	var decrypted []byte
	var err error
outer:
	for _, encrypted := range pal {
		for _, kak := range keyAgreementKIDs {
			log.Logger().Tracef("Trying key %s to decrypt PAL header...", kak)
			decrypted, err = decryptor.Decrypt(kak, encrypted)
			if errors.Is(err, crypto.ErrKeyNotFound) {
				return nil, fmt.Errorf("private key of DID keyAgreement not found (kid=%s)", kak)
			}
			if err != nil {
				log.Logger().Tracef("Unsuccessful: %v", err)
			} else {
				break outer
			}
		}
	}

	if len(decrypted) == 0 {
		// Could not decrypt, not for us.
		return nil, nil
	}

	var participants []did.DID
	for _, curr := range strings.Split(string(decrypted), "\n") {
		participant, err := did.ParseDID(curr)
		if err != nil {
			return nil, fmt.Errorf("invalid participant (did=%s): %w", curr, err)
		}
		participants = append(participants, *participant)
	}

	return participants, nil
}
