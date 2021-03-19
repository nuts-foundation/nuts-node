package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

//go:embed assets
var assets embed.FS

const assetsFolder = "assets"

func LoadEmbeddedTemplates() ([]ServiceTemplate, error) {
	results := make([]ServiceTemplate, 0)
	entries, _ := assets.ReadDir(assetsFolder)
	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := path.Join(assetsFolder, entry.Name())
			tplData, _ := assets.ReadFile(fileName)
			tpl := ServiceTemplate{}
			if err := json.Unmarshal(tplData, &tpl); err != nil {
				return nil, fmt.Errorf("invalid service template (%s): %w", fileName, err)
			}
			tpl.Name = strings.TrimSuffix(entry.Name(), ".json")
			results = append(results, tpl)
		}
	}
	return results, nil
}
