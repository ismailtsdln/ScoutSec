package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// JWTAnalyzer handles JWT token analysis and vulnerability detection.
type JWTAnalyzer struct{}

// NewJWTAnalyzer creates a new JWT analyzer.
func NewJWTAnalyzer() *JWTAnalyzer {
	return &JWTAnalyzer{}
}

// AnalyzeToken analyzes a JWT token for security issues.
func (ja *JWTAnalyzer) AnalyzeToken(tokenString string) error {
	// Parse without verification to inspect claims
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Check algorithm
	alg := token.Header["alg"]
	if alg == "none" {
		fmt.Println("[JWT] WARNING: Token uses 'none' algorithm (critical vulnerability)")
		report.AddIssue(report.Issue{
			Name:        "JWT None Algorithm",
			Description: "JWT uses 'none' algorithm, allowing signature bypass",
			Severity:    "Critical",
			URL:         "JWT Analysis",
			Evidence:    fmt.Sprintf("Algorithm: %v", alg),
		})
	}

	// Check for weak algorithms
	if alg == "HS256" {
		fmt.Println("[JWT] INFO: Token uses HS256 (symmetric). Check for key reuse.")
	}

	// Decode and inspect claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		ja.inspectClaims(claims)
	}

	return nil
}

func (ja *JWTAnalyzer) inspectClaims(claims jwt.MapClaims) {
	// Check expiration
	if exp, ok := claims["exp"]; ok {
		fmt.Printf("[JWT] Token expiration: %v\n", exp)
	} else {
		fmt.Println("[JWT] WARNING: No expiration claim found")
		report.AddIssue(report.Issue{
			Name:        "JWT Missing Expiration",
			Description: "JWT token does not have an expiration claim",
			Severity:    "Medium",
			URL:         "JWT Analysis",
			Evidence:    "Missing 'exp' claim",
		})
	}

	// Check for sensitive data in claims
	for key, value := range claims {
		if strings.Contains(strings.ToLower(key), "password") ||
			strings.Contains(strings.ToLower(key), "secret") {
			report.AddIssue(report.Issue{
				Name:        "JWT Sensitive Data Exposure",
				Description: fmt.Sprintf("JWT contains potentially sensitive claim: %s", key),
				Severity:    "High",
				URL:         "JWT Analysis",
				Evidence:    fmt.Sprintf("Claim: %s = %v", key, value),
			})
		}
	}
}

// DecodePayload decodes the JWT payload without verification.
func (ja *JWTAnalyzer) DecodePayload(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
