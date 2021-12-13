package dag

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
)

// palHeaderDIDSeparator holds the character(s) that separate DID entries in the PAL header, before being encrypted.
const palHeaderDIDSeparator = "\n"

// PAL holds the list of participants of a transaction.
type PAL []did.DID

// Encrypt encodes and encrypts the given participant DIDs.
// It uses the given types.KeyResolver to look up the public encryption key for each participant,
// and then encrypts the PAL header using each.
func (pal PAL) Encrypt(keyResolver types.KeyResolver) (EncryptedPAL, error) {
	var encryptionKeys []*ecdsa.PublicKey
	var recipients [][]byte
	for _, recipient := range pal {
		recipients = append(recipients, []byte(recipient.String()))
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
	plaintext := bytes.Join(recipients, []byte(palHeaderDIDSeparator))

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

// EncryptedPAL holds the list of participants of a transaction, but encrypted. It can be decrypted into a PAL.
type EncryptedPAL [][]byte

// Decrypt decrypts the given encrypted PAL header, yielding the decoded transaction participant DIDs.
// It attempts to decrypt the PAL header with the given keyAgreement keys, specified by key ID.
// If the header can't be decrypted with any of the given keys, nil (without an error) is returned.
// - If the header can be decrypted with (one of) the given keys, the DIDs are decoded and returned.
// An error is returned in the following cases:
// - If one of the attempted keyAgreement keys is not found or of an unsupported type, an error is returned.
// - If one of the decrypted participants isn't a valid DID.
func (epal EncryptedPAL) Decrypt(keyAgreementKIDs []string, decryptor crypto.Decryptor) (PAL, error) {
	var decrypted []byte
	var err error
outer:
	for _, encrypted := range epal {
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
	for _, curr := range strings.Split(string(decrypted), palHeaderDIDSeparator) {
		participant, err := did.ParseDID(curr)
		if err != nil {
			return nil, fmt.Errorf("invalid participant (did=%s): %w", curr, err)
		}
		participants = append(participants, *participant)
	}

	return participants, nil
}
