/*
 * Copyright (C) 2022 Nuts community
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

package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	irma "github.com/privacybydesign/irmago"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// NewIssuer creates a new issuer which implements the Issuer interface.
func NewIssuer(store Store, publisher Publisher, docResolver vdr.DocResolver, keyStore crypto.KeyStore, irmaConfig *irma.Configuration) Issuer {
	resolver := vdrKeyResolver{docResolver: docResolver, keyResolver: keyStore}
	return &issuer{
		store:       store,
		publisher:   publisher,
		keyResolver: resolver,
		irmaConfig:  irmaConfig,
	}
}

type issuer struct {
	store       Store
	publisher   Publisher
	keyResolver keyResolver
	irmaConfig  *irma.Configuration
}

// Issue creates a new credential, signs, stores it.
// If publish is true, it publishes the credential to the network using the configured Publisher
// Use the public flag to pass the visibility settings to the Publisher.
func (i issuer) Issue(credentialOptions vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error) {
	createdVC, err := i.buildVC(credentialOptions)
	if err != nil {
		return nil, err
	}

	validator, _ := credential.FindValidatorAndBuilder(*createdVC)
	if err := validator.Validate(*createdVC); err != nil {
		return nil, err
	}

	if err = i.store.StoreCredential(*createdVC); err != nil {
		return nil, fmt.Errorf("unable to store the issued credential: %w", err)
	}

	if publish {
		if err := i.publisher.PublishCredential(*createdVC, public); err != nil {
			return nil, fmt.Errorf("unable to publish the issued credential: %w", err)
		}
	}
	return createdVC, nil
}

func unflattenAttributes(attributes map[string]string) (map[string]interface{}, error) {
	output := map[string]interface{}{}

	for name, value := range attributes {
		data := output
		components := strings.Split(name, ".")

		for i, component := range components {
			if i == len(components)-1 {
				data[component] = value
				break
			}

			if group, ok := data[component]; ok {
				if data, ok = group.(map[string]interface{}); !ok {
					return nil, fmt.Errorf("invalid type for attribute %s", name)
				}
			} else {
				newMap := map[string]interface{}{}
				data[component] = newMap
				data = newMap
			}
		}
	}

	return output, nil
}

func (i issuer) buildVC(credentialOptions vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(credentialOptions.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	// find issuer
	issuer, err := did.ParseDID(credentialOptions.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	credentialID, _ := ssi.ParseURI(fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String()))
	unsignedCredential := vc.VerifiableCredential{
		Context:           append(credentialOptions.Context, vc.VCContextV1URI()),
		ID:                credentialID,
		Type:              credentialOptions.Type,
		CredentialSubject: credentialOptions.CredentialSubject,
		Issuer:            credentialOptions.Issuer,
		ExpirationDate:    credentialOptions.ExpirationDate,
		IssuanceDate:      time.Now(),
	}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !unsignedCredential.IsType(defaultType) {
		unsignedCredential.Type = append(unsignedCredential.Type, defaultType)
	}

	var vcData []byte

	if credentialOptions.Proof != nil {
		irmaProof := []proof.IRMASignatureProof{}

		if err := credentialOptions.UnmarshalProofValue(&irmaProof); err == nil {
			if len(irmaProof) != 1 {
				return nil, errors.New("can only issue credential with a single IRMA proof")
			}

			attributes, err := irmaProof[0].Verify(i.irmaConfig)
			if err != nil {
				return nil, fmt.Errorf("IRMA signature verification failed: %w", err)
			}

			subject, err := unflattenAttributes(attributes)
			if err != nil {
				return nil, err
			}

			subject["id"] = unsignedCredential.Issuer.String()

			unsignedCredential.CredentialSubject = []interface{}{subject}
			unsignedCredential.Proof = []interface{}{irmaProof[0]}

			vcData, err = json.Marshal(unsignedCredential)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("unsupported proof type: %s", irmaProof[0].Type)
		}
	} else {
		key, err := i.keyResolver.ResolveAssertionKey(*issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to sign credential, could not resolve an assertionKey for issuer: %w", err)
		}

		credentialAsMap := map[string]interface{}{}
		b, _ := json.Marshal(unsignedCredential)
		_ = json.Unmarshal(b, &credentialAsMap)

		signingResult, err := proof.LegacyLDProof{}.Sign(credentialAsMap, signature.LegacyNutsSuite{}, key)
		if err != nil {
			return nil, err
		}

		result, ok := signingResult.(map[string]interface{})
		if !ok {
			return nil, errors.New("unable to cast signing result to interface map")
		}

		vcData, err = json.Marshal(result)
		if err != nil {
			return nil, err
		}
	}

	signedCredential := &vc.VerifiableCredential{}

	if err := json.Unmarshal(vcData, signedCredential); err != nil {
		return nil, err
	}

	return signedCredential, nil
}

func (i issuer) Revoke(credentialID ssi.URI) error {
	//TODO implement me
	panic("implement me")
}

func (i issuer) CredentialResolver() CredentialSearcher {
	return i.store
}

func (i issuer) SearchCredential(context ssi.URI, credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	return i.store.SearchCredential(context, credentialType, issuer, subject)
}
