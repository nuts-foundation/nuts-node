package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func GetResponseBodyBytes(t *testing.T, visitor func(http.ResponseWriter) error) []byte {
	recorder := httptest.NewRecorder()
	if err := visitor(recorder); err != nil {
		t.Fatal(err)
	}
	return recorder.Body.Bytes()
}

func GetResponseBody(t *testing.T, visitor func(http.ResponseWriter) error) string {
	return string(GetResponseBodyBytes(t, visitor))
}

func UnmarshalResponseBody(t *testing.T, visitor func(http.ResponseWriter) error, target interface{}) {
	data := GetResponseBodyBytes(t, visitor)
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}