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

const moduleName = "VCR"

// Config holds the config for the vcr engine
type Config struct {
	// strictMode is a copy from the core server config
	strictMode bool
	// OverrideAllPublic overrides the "Public" property of a credential when issuing credentials:
	// if set to true, all issued credentials are published as public credentials, regardless of whether they're actually marked as public.
	OverrideIssueAllPublic bool `koanf:"vcr.overrideissueallpublic"`
	// datadir holds the location the VCR files are stored
	datadir        string
	JsonLdContexts JsonLdContexts `koanf:"vcr.jsonldcontexts"`
}

type JsonLdContexts struct {
	RemoteAllowList  []string      `koanf:"remoteallowlist"`
	LocalFileMapping []FileMapping `koanf:"localmapping"`
}

type FileMapping struct {
	Url  string `koanf:"url"`
	Path string `koanf:"path"`
}

// DefaultConfig returns a fresh Config filled with default values
func DefaultConfig() Config {
	return Config{
		OverrideIssueAllPublic: true,
		JsonLdContexts: JsonLdContexts{
			RemoteAllowList: DefaultAllowList(),
		},
	}
}

const SchemaOrgContext = "https://schema.org"
const W3cVcContext = "https://www.w3.org/2018/credentials/v1"
const Jws2020Context = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"

func DefaultAllowList() []string {
	return []string{SchemaOrgContext, W3cVcContext, Jws2020Context}
}
