package active

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
)

// MutatePayload applies various encodings to a payload.
func MutatePayload(content string) []string {
	mutations := []string{content}

	// URL Encoding
	mutations = append(mutations, url.QueryEscape(content))

	// Double URL Encoding
	mutations = append(mutations, url.QueryEscape(url.QueryEscape(content)))

	// Base64 Encoding
	mutations = append(mutations, base64.StdEncoding.EncodeToString([]byte(content)))

	// Hex Encoding
	mutations = append(mutations, hex.EncodeToString([]byte(content)))

	return mutations
}
