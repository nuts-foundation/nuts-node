package assets

import (
	"embed"
)

// FS can be used to access the embedded assets.
//go:embed certs
var FS embed.FS
