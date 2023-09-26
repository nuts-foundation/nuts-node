/*
 * Copyright (C) 2021 Nuts community
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

package dag

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"strings"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// palHeaderDIDSeparator holds the character(s) that separate DID entries in the PAL header, before being encrypted.
const palHeaderDIDSeparator = "\n"

// PAL holds the list of participants of a transaction.
type PAL []did.DID

// Contains returns `true` when the given DID is in the PAL
func (pal PAL) Contains(id did.DID) bool {
	for _, participant := range pal {
		if id.Equals(participant) {
			return true
		}
	}

	return false
}

// Encrypt encodes and encrypts the given participant DIDs.
// It uses the given types.KeyResolver to look up the public encryption key for each participant,
// and then encrypts the PAL header using each.
func (pal PAL) Encrypt(keyResolver resolver.KeyResolver) (EncryptedPAL, error) {
	var encryptionKeys []*ecdsa.PublicKey
	var recipients [][]byte
	for _, recipient := range pal {
		recipients = append(recipients, []byte(recipient.String()))
		_, rawKak, err := keyResolver.ResolveKey(recipient, nil, resolver.KeyAgreement)
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
func (epal EncryptedPAL) Decrypt(ctx context.Context, keyAgreementKIDs []string, decryptor crypto.Decrypter) (PAL, error) {
	var decrypted []byte
	var err error
outer:
	for _, encrypted := range epal {
		for _, kak := range keyAgreementKIDs {
			log.Logger().
				WithField(core.LogFieldKeyID, kak).
				Trace("Trying key to decrypt PAL header...")
			decrypted, err = decryptor.Decrypt(ctx, kak, encrypted)
			if errors.Is(err, crypto.ErrPrivateKeyNotFound) {
				return nil, fmt.Errorf("private key of DID keyAgreement not found (kid=%s)", kak)
			}
			if err != nil {
				log.Logger().
					WithError(err).
					Trace("Unsuccessful")
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
