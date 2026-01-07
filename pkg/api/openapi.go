package api

import (
	"context"
	"fmt"
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
)

// OpenAPIScanner handles OpenAPI/Swagger definition parsing and scanning.
type OpenAPIScanner struct {
	Doc *openapi3.T
}

// LoadFromURL loads an OpenAPI spec from a URL.
func LoadFromURL(specURL string) (*OpenAPIScanner, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromURI(&url.URL{Scheme: "https", Host: specURL})
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	// Validate the document
	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec: %w", err)
	}

	return &OpenAPIScanner{Doc: doc}, nil
}

// LoadFromFile loads an OpenAPI spec from a local file.
func LoadFromFile(filepath string) (*OpenAPIScanner, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec from file: %w", err)
	}

	// Validate the document
	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec: %w", err)
	}

	return &OpenAPIScanner{Doc: doc}, nil
}

// ExtractEndpoints extracts all API endpoints from the spec.
func (s *OpenAPIScanner) ExtractEndpoints() []Endpoint {
	var endpoints []Endpoint

	for path, pathItem := range s.Doc.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			endpoints = append(endpoints, Endpoint{
				Path:        path,
				Method:      method,
				Summary:     operation.Summary,
				Description: operation.Description,
			})
		}
	}

	return endpoints
}

// Endpoint represents a discovered API endpoint.
type Endpoint struct {
	Path        string
	Method      string
	Summary     string
	Description string
}
