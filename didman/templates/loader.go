package templates

import (
	"embed"
	"path"
	"strings"
)

//go:embed assets
var assets embed.FS

const assetsFolder = "assets"

func LoadEmbeddedDefinitions() ([]Definition, error) {
	results := make([]Definition, 0)
	entries, _ := assets.ReadDir(assetsFolder)
	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := path.Join(assetsFolder, entry.Name())
			tplData, _ := assets.ReadFile(fileName)
			template, err := parseMustacheTemplate(strings.TrimSuffix(entry.Name(), ".json"), string(tplData))
			if err != nil {
				return nil, err
			}
			results = append(results, template)
		}
	}
	return results, nil
}
