package iam

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHtmlCredentialRenderer_Render(t *testing.T) {
	var cred vc.VerifiableCredential
	err := cred.UnmarshalJSON([]byte(nutsOrgCredentialJSON))
	require.NoError(t, err)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	renderer := HtmlCredentialRenderer{DocumentLoader: jsonldManager.DocumentLoader()}

	result, err := renderer.Render(context.Background(), cred)

	require.NoError(t, err)
	require.NotNil(t, result)
}

const nutsOrgCredentialJSON = `
{
  "@context": [
    "https://nuts.nl/credentials/v1",
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "credentialSubject": {
    "id": "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey",
    "organization": {
      "city": "IJbergen",
      "name": "Because we care B.V."
    }
  },
  "id": "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#ec8af8cf-67d4-4b54-9bd6-8a861e729e11",
  "issuanceDate": "2022-06-01T15:34:40.65319+02:00",
  "issuer": "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey",
  "proof": {
    "created": "2022-06-01T12:00:00Z",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Za6h29jt9fJMUDs9wkkbZAtB3-PTHfGBhFzPGz_DkWXariFkPQdd75BZU9-tQraiA7X8wMSSKQuYnQsNXMxvmw",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"
  },
  "type": [
    "NutsOrganizationCredential",
    "VerifiableCredential"
  ]
}
`
