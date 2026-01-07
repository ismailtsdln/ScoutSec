package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAPIScanner(t *testing.T) {
	// Create a dummy OpenAPI spec file
	specContent := `
openapi: 3.0.0
info:
  title: Sample API
  version: 1.0.0
servers:
  - url: http://localhost:8080
paths:
  /users:
    get:
      parameters:
        - name: id
          in: query
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
`
	tmpfile, err := os.CreateTemp("", "openapi-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(specContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Mock server to receive fuzz requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify we receive fuzzing requests
		id := r.URL.Query().Get("id")
		if id == "" {
			return
		}
		// Simulate error on specific payload
		if id == "1 OR 1=1" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	scanner := NewScanner(tmpfile.Name(), nil)
	if scanner == nil {
		t.Fatal("Scanner should not be nil")
	}
}
