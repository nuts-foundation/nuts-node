package core

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

const oasSpecBaseURL = "/spec"

// NewOpenAPISpecRepository creates a repository that serves the OpenAPI specifications.
func NewOpenAPISpecRepository(sources []RoutableWithSpec) Routable {
	specs := make(map[string][]byte, 0)
	var paths = make([]string, 0)
	for _, source := range sources {
		name := strings.ToLower(source.Name())
		path := fmt.Sprintf("%s/%s/v%d.json", oasSpecBaseURL, name, source.Version())
		bytes, err := source.JsonSpec()
		if err != nil {
			// Should never happen, sourced from generated code
			Logger().Error("Unable to resolve OpenAPI spec: %s", err)
			continue
		}
		specs[path] = bytes
		paths = append(paths, path)
	}
	return oasRepository{specs: specs, paths: paths}
}

type oasRepository struct {
	paths []string
	specs map[string][]byte
}

func (o oasRepository) Routes(router EchoRouter) {
	// Register landing page
	router.GET(oasSpecBaseURL+"/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, o.paths)
	})
	// Register specs
	for path, bytes := range o.specs {
		cp := bytes[:]
		router.GET(path, func(c echo.Context) error {
			return c.Blob(http.StatusOK, "application/json", cp)
		})
	}
}
