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

// EncryptPAL encodes and encrypts the given participant DIDs as PAL header.
// It uses the given types.KeyResolver to look up the public encryption key for each participant,
// and then encrypts the PAL header using each.
func EncryptPAL(keyResolver types.KeyResolver, participants []did.DID) ([][]byte, error) {
	var encryptionKeys []*ecdsa.PublicKey
	var recipientStrs []string
	for _, recipient := range participants {
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

// DecryptPAL decrypts the given encrypted PAL header, yielding the decoded transaction participant DIDs.
// It attempts to decrypt the PAL header with the given keyAgreement keys, specified by key ID.
// If the header can't be decrypted with any of the given keys, nil (without an error) is returned.
// - If the header can be decrypted with (one of) the given keys, the DIDs are decoded and returned.
// An error is returned in the following cases:
// - If one of the attempted keyAgreement keys is not found or of an unsupported type, an error is returned.
// - If one of the decrypted participants isn't a valid DID.
func DecryptPAL(pal [][]byte, keyAgreementKIDs []string, decryptor crypto.Decryptor) ([]did.DID, error) {
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
