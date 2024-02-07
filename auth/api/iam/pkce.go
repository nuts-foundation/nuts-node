package iam

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

type PKCEParams struct {
	Challenge       string
	ChallengeMethod string
	Verifier        string
}

func randomString(n int) string {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func generatePKCEParams() *PKCEParams {
	verifier := randomString(32)
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
	return &PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}
