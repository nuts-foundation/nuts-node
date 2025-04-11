package test

import "encoding/json"

func remarshal(src interface{}, dst interface{}) error {
	asJSON, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(asJSON, &dst)
}

func MustRemarshalIntoMap(v interface{}) map[string]any {
	var result map[string]interface{}
	if err := remarshal(v, &result); err != nil {
		panic(err)
	}
	return result
}
