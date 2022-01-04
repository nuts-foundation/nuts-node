package proof

import (
	"embed"
	"errors"
	"fmt"
	"github.com/piprate/json-gold/ld"
	"io/fs"
	"net/url"
)

// embeddedFSDocumentLoader tries to load documents from an embedded filesystem.
type embeddedFSDocumentLoader struct {
	fs         embed.FS
	nextLoader ld.DocumentLoader
}

// NewEmbeddedFSDocumentLoader creates a new embeddedFSDocumentLoader for an embedded filesystem.
func NewEmbeddedFSDocumentLoader(fs embed.FS, nextLoader ld.DocumentLoader) *embeddedFSDocumentLoader {
	return &embeddedFSDocumentLoader{
		fs:         fs,
		nextLoader: nextLoader,
	}
}

// LoadDocument tries to load the document from the embedded filesystem.
// If the document is not a file or could not be found it tries the nextLoader.
func (e embeddedFSDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", u))
	}

	protocol := parsedURL.Scheme
	if protocol != "http" && protocol != "https" {
		remoteDoc := &ld.RemoteDocument{}
		file, err := e.fs.Open(u)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return e.nextLoader.LoadDocument(u)
			}
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		defer file.Close()
		remoteDoc.Document, err = ld.DocumentFromReader(file)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		return remoteDoc, nil
	}
	return e.nextLoader.LoadDocument(u)
}
