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
	"context"
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/pkg/errors"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/log"

	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

const revocationCollection = "_revocation"

// maxFindExecutionTime indicates how long a "find by id" type query may take
const maxFindExecutionTime = 1 * time.Second

type leiaCredentialStore struct {
	db      leia.Store
	configs []concept.Config
}

func NewLeiaStore(configs []concept.Config, dbPath string, noSync bool) (CredentialStoreBackend, error) {
	cs := &leiaCredentialStore{}
	var err error

	// setup DB connection
	if cs.db, err = leia.NewStore(dbPath, noSync); err != nil {
		return nil, err
	}

	if err = cs.initIndices(configs); err != nil {
		return nil, err
	}
	return cs, nil
}

func (c leiaCredentialStore) WriteCredential(subject vc.VerifiableCredential) error {
	// validation has made sure there's exactly one!
	vcType := credential.ExtractTypes(subject)[0]

	log.Logger().Debugf("Writing %s to store", vcType)
	log.Logger().Tracef("%+v", subject)

	doc, _ := json.Marshal(subject)

	collection := c.db.Collection(vcType)

	return collection.Add([]leia.Document{leia.DocumentFromBytes(doc)})
}

// SearchCredential for matching credentials based upon a query. It returns an empty list if no matches have been found.
func (c leiaCredentialStore) SearchCredential(ctx context.Context, query concept.Query) ([]vc.VerifiableCredential, error) {
	//transform query to leia query, for each template a query is returned
	queries := c.convert(query)

	var VCs = make([]vc.VerifiableCredential, 0)
	for vcType, q := range queries {
		docs, err := c.db.Collection(vcType).Find(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			foundCredential := vc.VerifiableCredential{}
			err = json.Unmarshal(doc.Bytes(), &foundCredential)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse credential from db")
			}

			VCs = append(VCs, foundCredential)
		}
	}

	return VCs, nil
}

// GetCredential only returns a VC from storage, it does not tell anything about validity
func (c leiaCredentialStore) GetCredential(ID ssi.URI) (vc.VerifiableCredential, error) {
	credential := vc.VerifiableCredential{}
	qp := leia.Eq(concept.IDField, ID.String())
	q := leia.New(qp)

	ctx, cancel := context.WithTimeout(context.Background(), maxFindExecutionTime)
	defer cancel()
	for _, t := range c.configs {
		docs, err := c.db.Collection(t.CredentialType).Find(ctx, q)
		if err != nil {
			return credential, err
		}
		if len(docs) > 0 {
			// there can be only one
			err = json.Unmarshal(docs[0].Bytes(), &credential)
			if err != nil {
				return credential, errors.Wrap(err, "unable to parse credential from db")
			}

			return credential, nil
		}
	}

	return credential, ErrNotFound
}

func (c leiaCredentialStore) WriteRevocation(r credential.Revocation) error {
	collection := c.revocationIndex()

	doc, _ := json.Marshal(r)

	return collection.Add([]leia.Document{leia.DocumentFromBytes(doc)})
}

// CredentialIssuers returns list of all known credential issuers for a specific type
func (c leiaCredentialStore) CredentialIssuers(credentialType ssi.URI) ([]ssi.URI, error) {
	// prevent duplicates by keeping a list of seen issuers
	seenIssuers := map[string]bool{}
	issuers := []ssi.URI{}

	// create a new query that matches all keys
	query := leia.New(leia.Prefix(concept.IssuerField, ""))

	// use type specific collection
	collection := c.db.Collection(credentialType.String())

	err := collection.IndexIterate(query, func(key []byte, value []byte) error {
		// we iterate over all issuers->reference pairs
		issuer := string(key)
		if _, ok := seenIssuers[issuer]; !ok {
			u, err := ssi.ParseURI(issuer)
			if err != nil {
				return err
			}
			issuers = append(issuers, *u)
			seenIssuers[issuer] = true
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, leia.ErrNoIndex) {
			log.Logger().Warnf("No index with field 'issuer' found for %s", credentialType.String())

			return nil, ErrInvalidCredential
		}
		return nil, err
	}

	return issuers, nil
}

func (c *leiaCredentialStore) IsCredentialRevoked(ID ssi.URI) (bool, error) {
	qp := leia.Eq(concept.SubjectField, ID.String())
	q := leia.New(qp)

	gIndex := c.revocationIndex()
	ctx, cancel := context.WithTimeout(context.Background(), maxFindExecutionTime)
	defer cancel()
	docs, err := gIndex.Find(ctx, q)
	if err != nil {
		return false, err
	}

	if len(docs) >= 1 {
		return true, nil
	}

	return false, nil
}

func (c *leiaCredentialStore) revocationIndex() leia.Collection {
	return c.db.Collection(revocationCollection)
}

func (c *leiaCredentialStore) initIndices(concepts []concept.Config) error {
	for _, config := range concepts {
		collection := c.db.Collection(config.CredentialType)
		for _, index := range config.Indices {
			var leiaParts []leia.FieldIndexer

			for _, iParts := range index.Parts {
				options := make([]leia.IndexOption, 0)
				if iParts.Alias != nil {
					options = append(options, leia.AliasOption(*iParts.Alias))
				}
				if iParts.Tokenizer != nil {
					tokenizer := strings.ToLower(*iParts.Tokenizer)
					switch tokenizer {
					case "whitespaceorexact":
						options = append(options, leia.TokenizerOption(whitespaceOrExactTokenizer))
					case "whitespace":
						options = append(options, leia.TokenizerOption(leia.WhiteSpaceTokenizer))
					default:
						return fmt.Errorf("unknown tokenizer %s for %s", *iParts.Tokenizer, config.CredentialType)
					}
				}
				if iParts.Transformer != nil {
					transformer := strings.ToLower(*iParts.Transformer)
					switch transformer {
					case "cologne":
						options = append(options, leia.TransformerOption(concept.CologneTransformer))
					case "lowercase":
						options = append(options, leia.TransformerOption(leia.ToLower))
					default:
						return fmt.Errorf("unknown transformer %s for %s", *iParts.Transformer, config.CredentialType)
					}
				}

				leiaParts = append(leiaParts, leia.NewFieldIndexer(iParts.JSONPath, options...))
			}

			leiaIndex := leia.NewIndex(index.Name, leiaParts...)
			log.Logger().Debugf("Adding index %s to %s using: %v", index.Name, config.CredentialType, leiaIndex)

			if err := collection.AddIndex(leiaIndex); err != nil {
				return err
			}
		}
	}

	// revocation indices
	rIndex := c.revocationIndex()
	return rIndex.AddIndex(leia.NewIndex("index_subject", leia.NewFieldIndexer(concept.SubjectField)))
}

// convert returns a map of credential type to query
// credential type is then used as collection input
func (c *leiaCredentialStore) convert(query concept.Query) map[string]leia.Query {
	var qs = make(map[string]leia.Query, 0)

	for _, tq := range query.Parts() {
		var q leia.Query
		for _, clause := range tq.Clauses {
			var qp leia.QueryPart

			switch clause.Type() {
			case concept.EqType:
				qp = leia.Eq(clause.Key(), clause.Seek())
			case concept.PrefixType:
				qp = leia.Prefix(clause.Key(), clause.Seek())
			default:
				qp = leia.Range(clause.Key(), clause.Seek(), clause.Match())
			}

			if q == nil {
				q = leia.New(qp)
			} else {
				q = q.And(qp)
			}
		}
		qs[tq.CredentialType()] = q
	}

	return qs
}

func whitespaceOrExactTokenizer(text string) (tokens []string) {
	tokens = leia.WhiteSpaceTokenizer(text)
	tokens = append(tokens, text)

	return
}

func (c leiaCredentialStore) Close() error {
	return c.db.Close()
}
