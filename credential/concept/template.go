/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package concept

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nuts-foundation/go-did"
	"github.com/thedevsaddam/gojsonq/v2"
)

// TypeField defines the concept/VC JSON path to a VC type
const TypeField = "type"

// IDField defines the concept/VC JSON path to a VC ID
const IDField = "id"

// IssuerField defines the concept/VC JSON path to a VC issuer
const IssuerField = "issuer"

// SubjectField defines the concept JSON path to a VC subject
const SubjectField = "subject"

// Template represents a json mapping template. In the template concept to json path mappings are stored.
// Indices that need to be created by a DB are also created by the template.
type Template interface {
	// Indices returns a list of compound indices. Each entry contains the concept json path.
	Indices() [][]string
	// VCType returns the VC type.
	VCType() string
	// ToVCPath returns the mapping of concept path to VC path
	ToVCPath(conceptPath string) string
}

type template struct {
	raw string
	// conceptIndexMapping contains mappings from concept name to VC JSON path
	conceptIndexMapping map[string]string
	// reverseIndexMapping contains mappings from VC JSON path to concept JSON path
	reverseIndexMapping map[string]string
	// indices contains a set of compound indices
	indices [][]string
	// key: value pairs that always need to be added to the backend query
	fixedValues map[string]string
}

// templateString represents a value in a template.
// it contains several convenience methods for parsing purposes
type templateString string

// ToVCPath returns the mapping of concept path to VC path
func (ct *template) ToVCPath(conceptPath string) string {
	return ct.conceptIndexMapping[conceptPath]
}

func (ct *template) Indices() [][]string {
	return ct.indices
}

// VCType returns the VC type.
func (ct *template) VCType() string {
	return ct.fixedValues[TypeField]
}

// find paths to concepts
func (ct *template) parse() error {
	jq := gojsonq.New().FromString(ct.raw)

	// type is a special pony
	ct.conceptIndexMapping = map[string]string{TypeField: TypeField}
	ct.reverseIndexMapping = map[string]string{TypeField: TypeField}
	ct.fixedValues = map[string]string{}

	if err := ct.mapR(jq, ""); err != nil {
		return err
	}

	return nil
}

func (ct *template) concepts() []string {
	var cs = make([]string, 0)

	// standard concepts not needed
	for k := range ct.conceptIndexMapping {
		s := strings.Split(k, ".")
		if len(s) > 1 {
			cs = append(cs, k)
		}
	}

	return cs
}
func (ct *template) rootConcepts() []string {
	var cm = make(map[string]bool, 0)

	// all concepts
	for _, c := range ct.concepts() {
		cm[strings.Split(c, ".")[0]] = true
	}

	// uniq concepts
	var cs = make([]string, 0)
	for k := range cm {
		cs = append(cs, k)
	}

	return cs
}

func (ct *template) mapR(jq *gojsonq.JSONQ, currentPath string) error {
	val := jq.Get()

	if jq.Error() != nil {
		return jq.Error()
	}

	// slice
	if _, ok := val.([]interface{}); ok {
		return errors.New("json arrays are not supported")
	}

	if m, ok := val.(map[string]interface{}); ok {
		for k, v := range m {
			nextPath := path(currentPath, k)

			if sv, ok := v.(string); ok {
				if err := ct.processValue(sv, nextPath); err != nil {
					return err
				}
			} else {
				gjs := gojsonq.New().FromInterface(v)
				if err := ct.mapR(gjs, nextPath); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (ct *template) processValue(value string, currentPath string) error {
	processValue := templateString(value)

	if !processValue.isValid() {
		return fmt.Errorf("values has incorrect format at %s: %s", currentPath, value)
	}

	if processValue.isHardCoded() {
		ct.fixedValues[currentPath] = processValue.String()
	} else {
		ct.conceptIndexMapping[processValue.String()] = currentPath
		ct.reverseIndexMapping[currentPath] = processValue.String()
	}

	if processValue.hasIndex() {
		for _, index := range processValue.indices() {
			ct.addIndex(index[0], index[1], currentPath)
		}
	}

	return nil
}

// addIndex expects lvl Indices to start at 1
func (ct *template) addIndex(lvl1 int, lvl2 int, jsonPath string) {
	//always replace & copy => less if/else logic
	lvl1Size := max(len(ct.indices), lvl1)
	newLvl1 := make([][]string, lvl1Size)
	for i, v := range ct.indices {
		newLvl1[i] = v
	}

	lvl2Size := max(len(newLvl1[lvl1-1]), lvl2)
	newLvl2 := make([]string, lvl2Size)
	for i, v := range newLvl1[lvl1-1] {
		newLvl2[i] = v
	}
	ct.indices = newLvl1
	ct.indices[lvl1-1] = newLvl2
	ct.indices[lvl1-1][lvl2-1] = ct.reverseIndexMapping[jsonPath]
}

// transform a VC to a concept given the template mapping
func (ct *template) transform(VC did.VerifiableCredential) (Concept, error) {
	// remove type as this will be hardcoded later
	VC.Type = nil

	vcJSON, err := json.Marshal(VC)
	if err != nil {
		return nil, err
	}

	// json parsing
	jq := gojsonq.New()
	jq.FromString(string(vcJSON))

	// result target
	c := Concept{
		TypeField: ct.fixedValues[TypeField],
	}
	err = ct.transR(jq, "", c)

	return c, err
}

func (ct *template) transR(jq *gojsonq.JSONQ, currentPath string, c Concept) error {
	val := jq.Get()

	if jq.Error() != nil {
		return jq.Error()
	}

	// we do not support mapped values within lists
	if _, ok := val.([]interface{}); ok {
		return errors.New("json arrays are not supported")
	}

	if m, ok := val.(map[string]interface{}); ok {
		for k, v := range m {
			nextPath := path(currentPath, k)

			if v == nil {
				continue
			}

			if sv, ok := v.(string); ok {
				if m, ok := ct.reverseIndexMapping[nextPath]; ok {
					c.SetValue(m, sv)
				}
			} else {
				gjs := gojsonq.New().FromInterface(v)
				if err := ct.transR(gjs, nextPath, c); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (cs templateString) isHardCoded() bool {
	return !strings.Contains(string(cs), "<<")
}

func (cs templateString) hasIndex() bool {
	return strings.Contains(string(cs), "@")
}

var regex, _ = regexp.Compile("((<<[a-zA-Z\\.]+>>)|([a-zA-Z\\.]+))(@({[1-9](_[1-9])?})(,{[1-9](_[1-9])?})*)?")

func (cs templateString) isValid() bool {
	s := regex.ReplaceAllString(string(cs), "")
	return len(s) == 0
}

// String returns the hardCoded string or the value between << and >>
func (cs templateString) String() string {
	// expect "?(<<)text?(>>)?(@{x,y})"
	processValue := string(cs)
	if i := strings.Index(processValue, "@"); i != -1 && i < len(cs) {
		processValue = processValue[0:i]
	}

	if strings.HasPrefix(processValue, "<<") && strings.HasSuffix(processValue, ">>") {
		processValue = processValue[2 : len(processValue)-2]
	}

	return processValue
}

func (cs templateString) indices() [][]int {
	// expect "*{x,y})"
	var indices [][]int
	s := string(cs)
	i := strings.Index(s, "@")
	is := s[i+1:]

	split := strings.Split(is, ",")
	for _, partial := range split {
		iVal := partial[1 : len(partial)-1]
		iSplit := strings.Split(iVal, "_")
		lvl2 := int64(1)
		lvl1, _ := strconv.ParseInt(iSplit[0], 0, 0)

		index := []int{int(lvl1), int(lvl2)}

		if len(iSplit) > 1 {
			lvl2, _ = strconv.ParseInt(iSplit[1], 0, 0)
			index[1] = int(lvl2)
		}
		indices = append(indices, index)
	}
	return indices
}
