package assets

import (
	"embed"
	"html/template"
)

//go:embed *.html
var assets embed.FS

// ErrorTemplate is the template used to render error pages.
var ErrorTemplate *template.Template

func init() {
	templates := template.Must(template.ParseFS(assets, "*.html"))
	ErrorTemplate = templates.Lookup("error.html")
}
