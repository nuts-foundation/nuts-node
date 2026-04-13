/*
 * Copyright (C) 2023 Nuts community
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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
	"io"
	"os"
	"strings"
)

func (sp ScopePolicy) valid() bool {
	switch sp {
	case ScopePolicyProfileOnly, ScopePolicyPassthrough, ScopePolicyDynamic:
		return true
	default:
		return false
	}
}

var _ PDPBackend = (*LocalPDP)(nil)

// New creates a new local policy backend
func New() *LocalPDP {
	return &LocalPDP{}
}

// LocalPDP is a backend for presentation definitions.
// It loads policy files that map OAuth scopes to credential profiles (PresentationDefinitions + scope policy).
type LocalPDP struct {
	config Config
	// mapping holds the credential profile configuration per scope
	mapping map[string]credentialProfileConfig
}

func (b *LocalPDP) Name() string {
	return ModuleName
}

func (b *LocalPDP) Configure(_ core.ServerConfig) error {
	if b.config.Directory != "" {
		_, err := os.Stat(b.config.Directory)
		if err != nil {
			if os.IsNotExist(err) && b.config.Directory == defaultConfig().Directory {
				// assume this is the default config value and remove it
				b.config.Directory = ""
			} else {
				return fmt.Errorf("failed to load policy from directory: %w", err)
			}
		}
	}
	if b.config.Directory != "" {
		if err := b.loadFromDirectory(b.config.Directory); err != nil {
			return fmt.Errorf("failed to load policy from directory: %w", err)
		}
	}
	if b.config.AuthZen.Endpoint == "" {
		for scope, profile := range b.mapping {
			if profile.ScopePolicy == ScopePolicyDynamic {
				return fmt.Errorf("credential profile %q has scope_policy %q but no AuthZen endpoint is configured (policy.authzen.endpoint)", scope, ScopePolicyDynamic)
			}
		}
	}
	return nil
}

func (b *LocalPDP) Config() interface{} {
	return &b.config
}

func (b *LocalPDP) FindCredentialProfile(_ context.Context, scope string) (*CredentialProfileMatch, error) {
	var profileScope string
	var profile credentialProfileConfig
	var otherScopes []string
	for _, s := range strings.Split(scope, " ") {
		if s == "" {
			continue
		}
		if p, exists := b.mapping[s]; exists {
			if profileScope != "" {
				return nil, fmt.Errorf("%w: multiple credential profile scopes found", ErrNotFound)
			}
			profileScope = s
			profile = p
		} else {
			otherScopes = append(otherScopes, s)
		}
	}
	if profileScope == "" {
		return nil, ErrNotFound
	}
	return &CredentialProfileMatch{
		CredentialProfileScope: profileScope,
		WalletOwnerMapping:     profile.toWalletOwnerMapping(),
		ScopePolicy:            profile.ScopePolicy,
		OtherScopes:            otherScopes,
	}, nil
}

// loadFromDirectory traverses all .json files in the given directory and loads them
func (b *LocalPDP) loadFromDirectory(directory string) error {
	// open the directory
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()

	// read all the files in the directory
	files, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	// load all the files
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		err := b.loadFromFile(fmt.Sprintf("%s/%s", directory, file.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *LocalPDP) loadFromFile(filename string) error {
	reader, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	result := make(map[string]credentialProfileConfig)
	if err = json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("failed to unmarshal PEX Policy mapping file %s: %w", filename, err)
	}
	if b.mapping == nil {
		b.mapping = make(map[string]credentialProfileConfig)
	}
	for scope, profile := range result {
		if _, exists := b.mapping[scope]; exists {
			return fmt.Errorf("mapping for scope '%s' already exists (file=%s)", scope, filename)
		}
		// Default to profile-only when scope_policy is not specified
		if profile.ScopePolicy == "" {
			profile.ScopePolicy = ScopePolicyProfileOnly
		}
		if !profile.ScopePolicy.valid() {
			return fmt.Errorf("invalid scope_policy %q for scope %q (file=%s)", profile.ScopePolicy, scope, filename)
		}
		b.mapping[scope] = profile
	}
	return nil
}

// credentialProfileConfig holds the configuration for a single credential profile.
type credentialProfileConfig struct {
	Organization *validatingPresentationDefinition `json:"organization,omitempty"`
	User         *validatingPresentationDefinition `json:"user,omitempty"`
	ScopePolicy  ScopePolicy                       `json:"scope_policy,omitempty"`
}

func (c *credentialProfileConfig) toWalletOwnerMapping() pe.WalletOwnerMapping {
	m := pe.WalletOwnerMapping{}
	if c.Organization != nil {
		m[pe.WalletOwnerOrganization] = pe.PresentationDefinition(*c.Organization)
	}
	if c.User != nil {
		m[pe.WalletOwnerUser] = pe.PresentationDefinition(*c.User)
	}
	return m
}

// validatingPresentationDefinition validates the PresentationDefinition against the v2 JSON schema on unmarshal.
type validatingPresentationDefinition pe.PresentationDefinition

func (v *validatingPresentationDefinition) UnmarshalJSON(data []byte) error {
	if err := v2.Validate(data, v2.PresentationDefinition); err != nil {
		return err
	}
	return json.Unmarshal(data, (*pe.PresentationDefinition)(v))
}
