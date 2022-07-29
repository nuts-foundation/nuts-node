/*
 * Nuts node
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

package vcr

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/nuts-foundation/nuts-node/vcr/types"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/log"

	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

const revocationCollection = "_revocation"

// maxFindExecutionTime indicates how long a "find by id" type query may take
const maxFindExecutionTime = 1 * time.Second

func (c *vcr) StoreCredential(credential vc.VerifiableCredential, validAt *time.Time) error {
	// ID must be unique
	if credential.ID != nil {
		existingCredential, err := c.find(*credential.ID)
		if err == nil {
			if reflect.DeepEqual(existingCredential, credential) {
				log.Logger().
					WithField("credentialID", *credential.ID).
					Info("Credential already exists", credential.ID)
				return nil
			}
			return fmt.Errorf("credential with same ID but different content already exists (id=%s)", credential.ID)
		} else if !errors.Is(err, types.ErrNotFound) {
			return err
		}
	}

	// verify first
	if err := c.verifier.Validate(credential, validAt); err != nil {
		return err
	}

	return c.writeCredential(credential)
}

func (c *vcr) writeCredential(subject vc.VerifiableCredential) error {
	// validation has made sure there's exactly one!
	vcType := credential.ExtractTypes(subject)[0]

	log.Logger().Debugf("Writing %s to store", vcType)
	log.Logger().Tracef("%+v", subject)

	doc, _ := json.Marshal(subject)

	return c.credentialCollection().Add([]leia.Document{doc})
}
