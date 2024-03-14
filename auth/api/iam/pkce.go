package iam

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/nuts-foundation/nuts-node/crypto"
)

type PKCEParams struct {
	Challenge       string
	ChallengeMethod string
	Verifier        string
}

func generatePKCEParams() *PKCEParams {
	verifier := crypto.GenerateNonce()
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
	return &PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}
