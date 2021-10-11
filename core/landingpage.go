package core

import (
	"embed"
	"github.com/labstack/echo/v4"
	"net/http"
)

//go:embed landingpage.html
var landingPageResource embed.FS

// LandingPage is a Routable that exposes a landing page at the node's HTTP root (`/`).
type LandingPage struct{}

// Routes registers the landing page on the given EchoRouter.
func (l LandingPage) Routes(router EchoRouter) {
	router.Add("GET", "/", func(context echo.Context) error {
		contents, err := l.load()
		if err != nil {
			return err
		}
		return context.HTML(http.StatusOK, contents)
	})
}

func (l LandingPage) load() (string, error) {
	contents, err := landingPageResource.ReadFile("landingpage.html")
	if err != nil {
		return "", err
	}
	return string(contents), nil
}
