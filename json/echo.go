package json

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/sugawarayuuta/sonnet"
	"net/http"
)

type SonnetJSONSerializer struct {
}

// Serialize converts an interface into a json and writes it to the response.
// You can optionally use the indent parameter to produce pretty JSONs.
func (d SonnetJSONSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	enc := NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(i)
}

// Deserialize reads a JSON from a request body and converts it into an interface.
func (d SonnetJSONSerializer) Deserialize(c echo.Context, i interface{}) error {
	err := NewDecoder(c.Request().Body).Decode(i)
	if ute, ok := err.(*sonnet.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*sonnet.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}
