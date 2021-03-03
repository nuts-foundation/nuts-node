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

package credential

import (
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did"
)

const defaultContext = "https://www.w3.org/2018/credentials/v1"
const nutsContext = "https://nuts.nl/credentials/v1"
const defaultType = "VerifiableCredential"

// Builder is an abstraction for extending a partial VC into a fully valid VC
type Builder interface {
	// Type returns the matching Verifiable Credential type
	Type() string
	// Build sets the defaults for common fields and creates the signature
	Build(vc *did.VerifiableCredential, fn FnProofBuilder) error
}

// defaultBuilder fills in the type, issuanceDate and context
type defaultBuilder struct {
	vcType string
}

//{
//"type": "EcdsaSecp256r1Signature2019",
//"created": "2017-06-18T21:19:10Z",
//"proofPurpose": "assertionMethod",
//"verificationMethod": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#90382475609238467#qjHYrzaJjpEstmDATng4-cGmR4t-_V3ipbDVYZrVe4A",
//"jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5X
//sITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUc
//X16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtj
//PAYuNzVBAh4vGHSrQyHUdBBPM"
//}

// header {"alg":"ES256","b64":false,"crit":["b64"]}
// payload: the VC in detached form
// sig type: JsonWebSignature2020

// FnProofBuilder is a function that generates the proof on a credential
type FnProofBuilder func(vc *did.VerifiableCredential) error

type JsonWebSignature2020Proof struct {
	did.Proof
	Jws string `json:"jws"`
}

func (d defaultBuilder) Build(vc *did.VerifiableCredential, fn FnProofBuilder) error {
	u, _ := url.Parse(defaultContext)
	u2, _ := url.Parse(nutsContext)
	vc.Context = []did.URI{{*u}, {*u2}}

	u3, _ := url.Parse(defaultType)
	vc.Type = append(vc.Type, did.URI{URL: *u3})
	vc.IssuanceDate = time.Now()
	vc.ID = generateID(vc.Issuer)

	return fn(vc)
}

func (d defaultBuilder) Type() string {
	return d.vcType
}

func generateID(issuer did.URI) *did.URI {
	id := fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String())
	u, _ := url.Parse(id)
	return &did.URI{URL: *u}
}

