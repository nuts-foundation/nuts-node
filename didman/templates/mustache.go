package templates

import (
	"encoding/json"
	"fmt"
	"github.com/cbroglie/mustache"
	errors2 "github.com/pkg/errors"
)

type mustacheJSONTemplate struct {
	name string
	tpl  *mustache.Template
}

func parseMustacheTemplate(name, raw string) (Definition, error) {
	tpl, err := mustache.ParseString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}
	return &mustacheJSONTemplate{
		name: name,
		tpl:  tpl,
	}, nil
}

func (m mustacheJSONTemplate) Name() string {
	return m.name
}

func (m mustacheJSONTemplate) Interpolate(parameters map[string]string) (ServiceTemplate, error) {
	mustache.AllowMissingVariables = false

	result := ServiceTemplate{}
	rendered, err := m.tpl.Render(parameters)
	if err != nil {
		return ServiceTemplate{}, errors2.Wrap(ErrInvalidServiceTemplateParameters, err.Error())
	}
	if err := json.Unmarshal([]byte(rendered), &result); err != nil {
		return ServiceTemplate{}, err
	}
	return result, nil
}
