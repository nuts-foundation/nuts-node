package signature

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/piprate/json-gold/ld"
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
func (e embeddedFSDocumentLoader) LoadDocument(path string) (*ld.RemoteDocument, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", path))
	}

	protocol := parsedURL.Scheme
	if protocol != "http" && protocol != "https" {
		remoteDoc := &ld.RemoteDocument{}
		remoteDoc.DocumentURL = path
		file, err := e.fs.Open(path)
		if err != nil {
			return e.nextLoader.LoadDocument(path)
		}
		defer file.Close()
		remoteDoc.Document, err = ld.DocumentFromReader(file)
		if err != nil {
			return nil, err
		}
		return remoteDoc, nil
	}
	return e.nextLoader.LoadDocument(path)
}

// LDUtil package a set of often used JSON-LD operations for re-usability.
type LDUtil struct {
	LDDocumentLoader ld.DocumentLoader
}

// Canonicalize canonicalizes the json-ld input according to the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm.
func (util LDUtil) Canonicalize(input interface{}) (result interface{}, err error) {
	var optionsMap map[string]interface{}
	inputAsJSON, _ := json.Marshal(input)
	if err := json.Unmarshal(inputAsJSON, &optionsMap); err != nil {
		return nil, err
	}
	proc := ld.NewJsonLdProcessor()

	normalizeOptions := ld.NewJsonLdOptions("")
	normalizeOptions.DocumentLoader = util.LDDocumentLoader
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	result, err = proc.Normalize(optionsMap, normalizeOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}
	return
}
