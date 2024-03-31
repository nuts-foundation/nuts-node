package assets

import (
	"embed"
	"html/template"
)

//go:embed *.html
var assets embed.FS

var Templates *template.Template

func init() {
	Templates = template.Must(template.ParseFS(assets, "*.html"))
}

func Template(name string) *template.Template {
	return Templates.Lookup(name)
}
