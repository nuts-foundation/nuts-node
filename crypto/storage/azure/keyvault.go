/*
 * Copyright (C) 2024 Nuts community
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

package azure

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	DefaultChainCredentialType    string = "default"
	ManagedIdentityCredentialType string = "managed_identity"
)

var _ spi.Storage = (*Keyvault)(nil)

// New creates a new Azure Key Vault storage backend.
// If useHSM is true, the key type will be azkeys.KeyTypeECHSM, otherwise azkeys.KeyTypeEC.
func New(config Config) (*Keyvault, error) {
	if config.URL == "" {
		return nil, errors.New("missing Azure Key Vault URL")
	}
	credential, err := createCredential(config.Auth.Type)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(config.URL, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create Azure Key Vault client: %w", err)
	}
	return &Keyvault{client: client, timeOut: config.Timeout, useHSM: config.UseHSM}, nil
}

func createCredential(credentialType string) (azcore.TokenCredential, error) {
	switch credentialType {
	case DefaultChainCredentialType:
		return azidentity.NewDefaultAzureCredential(nil)
	case ManagedIdentityCredentialType:
		return azidentity.NewManagedIdentityCredential(nil)
	default:
		return nil, fmt.Errorf("unsupported Azure Key Vault credential type: %s", credentialType)
	}
}

// StorageType is the name of this storage type, used in health check reports and configuration.
const StorageType = "azure-keyvault"

type Keyvault struct {
	client  keyVaultClient
	timeOut time.Duration
	useHSM  bool
}

func (a Keyvault) Name() string {
	return StorageType
}

func (a Keyvault) CheckHealth() map[string]core.Health {
	return nil
}

func (a Keyvault) NewPrivateKey(ctx context.Context, keyName string) (crypto.PublicKey, string, error) {
	var keyType azkeys.KeyType
	if a.useHSM {
		keyType = azkeys.KeyTypeECHSM
	} else {
		keyType = azkeys.KeyTypeEC
	}

	response, err := a.client.CreateKey(ctx, keyName, azkeys.CreateKeyParameters{
		Kty:   to.Ptr(keyType),
		Curve: to.Ptr(azkeys.CurveNameP256),
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled:    to.Ptr(true),
			Exportable: to.Ptr(false),
		},
	}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("unable to create key in Azure Key Vault (name=%s): %w", keyName, err)
	}
	publicKey, _, version, err := parseKey(response.Key)
	if err != nil {
		return nil, "", err
	}
	return publicKey, version, nil
}

func (a Keyvault) GetPrivateKey(ctx context.Context, keyName string, version string) (crypto.Signer, error) {
	response, err := a.getPrivateKey(ctx, keyName, version)
	if err != nil {
		return nil, err
	}
	publicKey, signingAlgorithm, _, err := parseKey(response.Key)
	if err != nil {
		return nil, err
	}
	return &azureSigningKey{
		client:           a.client,
		timeOut:          a.timeOut,
		keyName:          keyName,
		publicKey:        publicKey,
		signingAlgorithm: signingAlgorithm,
	}, nil
}

func (a Keyvault) PrivateKeyExists(ctx context.Context, keyName string, version string) (bool, error) {
	_, err := a.getPrivateKey(ctx, keyName, version)
	if errors.Is(err, spi.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (a Keyvault) DeletePrivateKey(ctx context.Context, keyName string) error {
	_, err := a.client.DeleteKey(ctx, keyName, nil)
	responseError := new(azcore.ResponseError)
	if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
		return spi.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("unable to delete key from Azure Key Vault (name=%s): %w", keyName, err)
	}
	return nil
}

func (a Keyvault) getPrivateKey(ctx context.Context, keyName string, version string) (*azkeys.GetKeyResponse, error) {
	response, err := a.client.GetKey(ctx, keyName, version, nil)
	responseError := new(azcore.ResponseError)
	if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
		return nil, spi.ErrNotFound
	} else if err != nil {
		// other error
		return nil, fmt.Errorf("unable to get key from Azure Key Vault (name=%s): %w", keyName, err)
	}
	return &response, nil
}

func (a Keyvault) SavePrivateKey(ctx context.Context, kid string, key crypto.PrivateKey) error {
	// Only used for migrating to a new storage backend, which is not implemented yet for Azure Key Vault
	return errors.New("SavePrivateKey() is not supported for Azure Key Vault")
}

func (a Keyvault) ListPrivateKeys(ctx context.Context) []spi.KeyNameVersion {
	pager := a.client.NewListKeyPropertiesPager(nil)
	result := make([]spi.KeyNameVersion, 0)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Logger().WithError(err).Error("unable to list keys from Azure Key Vault")
			return nil
		}
		for _, keyProperties := range page.Value {
			result = append(result, spi.KeyNameVersion{KeyName: keyProperties.KID.Name(), Version: keyProperties.KID.Version()})
		}
	}
	return result
}

// parseKey parses an Azure Key Vault key into a crypto.PublicKey and selects the azkeys.SignatureAlgorithm.
func parseKey(key *azkeys.JSONWebKey) (publicKey crypto.PublicKey, keyType azkeys.SignatureAlgorithm, version string, err error) {
	jwkData, _ := json.Marshal(key)
	keyAsJWK, err := jwk.ParseKey(jwkData)
	if err != nil {
		err = fmt.Errorf("unable to parse key from Azure Key Vault as JWK: %w", err)
		return
	}
	if err = keyAsJWK.Raw(&publicKey); err != nil {
		err = fmt.Errorf("unable to convert key from Azure Key Vault Key to crypto.PublicKey: %w", err)
		return
	}
	if !(*key.Kty == azkeys.KeyTypeEC || *key.Kty == azkeys.KeyTypeECHSM) || *key.Crv != azkeys.CurveNameP256 {
		err = errors.New("only ES256 keys are supported")
		return
	}
	keyType = azkeys.SignatureAlgorithmES256
	if key.KID == nil {
		err = errors.New("missing KID in key")
		return
	}
	version = key.KID.Version()
	return
}

var _ crypto.Signer = &azureSigningKey{}

type azureSigningKey struct {
	client           keyVaultClient
	timeOut          time.Duration
	keyName          string
	publicKey        crypto.PublicKey
	signingAlgorithm azkeys.SignatureAlgorithm
}

func (a azureSigningKey) Public() crypto.PublicKey {
	return a.publicKey
}

func (a azureSigningKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeOut)
	defer cancel()
	// Sanity check
	if opts != nil && opts.HashFunc() == 0 {
		return nil, errors.New("hashing should've been done")
	}
	response, err := a.client.Sign(ctx, a.keyName, "", azkeys.SignParameters{
		Algorithm: to.Ptr(a.signingAlgorithm),
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to sign with Azure Key Vault: %w", err)
	}
	// Azure Key Vault returns the signature in a []byte with r and s components concatenated.
	// We need to convert it to an ASN.1-encoded signature. The first half of the signature is r, the second half is s.
	return encodeSignature(response.Result[:len(response.Result)/2], response.Result[len(response.Result)/2:])
}

// encodeSignature was copied from ecdsa/ecdsa.go#encodeSignature()
func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes was copied from ecdsa/ecdsa.go#addASN1IntBytes()
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 { // note: this has to do with signed/unsigned requiring leading zero
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}
