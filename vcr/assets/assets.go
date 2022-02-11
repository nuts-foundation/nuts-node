package assets

import "embed"

// Assets contains the embedded files needed for VCR.
// These are the concept templates and de JSON-LD Contexts.
//go:embed assets/*
var Assets embed.FS
