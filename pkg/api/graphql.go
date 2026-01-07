package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// GraphQLFuzzer handles GraphQL-specific testing.
type GraphQLFuzzer struct {
	Endpoint string
	Client   *http.Client
}

// NewGraphQLFuzzer creates a new GraphQL fuzzer.
func NewGraphQLFuzzer(endpoint string) *GraphQLFuzzer {
	return &GraphQLFuzzer{
		Endpoint: endpoint,
		Client:   &http.Client{},
	}
}

// IntrospectionQuery performs GraphQL introspection to discover schema.
func (g *GraphQLFuzzer) IntrospectionQuery() (bool, error) {
	introspection := map[string]interface{}{
		"query": `{
			__schema {
				types {
					name
					fields {
						name
					}
				}
			}
		}`,
	}

	jsonData, _ := json.Marshal(introspection)
	req, _ := http.NewRequest("POST", g.Endpoint, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check if introspection is enabled
	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if _, ok := result["data"]; ok {
				fmt.Println("[GraphQL] Introspection is ENABLED (potential info disclosure)")
				report.AddIssue(report.Issue{
					Name:        "GraphQL Introspection Enabled",
					Description: "GraphQL introspection is enabled, exposing full schema",
					Severity:    "Medium",
					URL:         g.Endpoint,
					Evidence:    "Introspection query returned full schema",
				})
				return true, nil
			}
		}
	}

	return false, nil
}

// FuzzQueries tests common GraphQL vulnerabilities.
func (g *GraphQLFuzzer) FuzzQueries() {
	// Test for batch query attacks (DOS)
	g.testBatchQueryDOS()

	// Test for recursive queries (DOS)
	g.testRecursiveQuery()
}

func (g *GraphQLFuzzer) testBatchQueryDOS() {
	// Batch query attack: send many queries in one request
	query := `[`
	for i := 0; i < 100; i++ {
		query += `{"query": "{ __typename }"}`
		if i < 99 {
			query += ","
		}
	}
	query += `]`

	req, _ := http.NewRequest("POST", g.Endpoint, bytes.NewBufferString(query))
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		report.AddIssue(report.Issue{
			Name:        "GraphQL Batch Query DOS",
			Description: "Server accepts batch queries without rate limiting",
			Severity:    "Medium",
			URL:         g.Endpoint,
			Evidence:    "100 queries processed in single request",
		})
	}
}

func (g *GraphQLFuzzer) testRecursiveQuery() {
	// Test for deeply nested query (DOS)
	recursiveQuery := map[string]interface{}{
		"query": `{
			user {
				posts {
					author {
						posts {
							author {
								posts {
									author {
										name
									}
								}
							}
						}
					}
				}
			}
		}`,
	}

	jsonData, _ := json.Marshal(recursiveQuery)
	req, _ := http.NewRequest("POST", g.Endpoint, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// If server processes without depth limit, it's vulnerable
	if resp.StatusCode == 200 {
		report.AddIssue(report.Issue{
			Name:        "GraphQL Recursive Query Vulnerability",
			Description: "Server processes deeply nested queries without depth limit",
			Severity:    "Medium",
			URL:         g.Endpoint,
			Evidence:    "Recursive query with 5+ levels processed",
		})
	}
}
