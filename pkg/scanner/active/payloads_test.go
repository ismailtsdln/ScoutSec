package active

import (
	"testing"
)

func TestGetDefaultPayloads(t *testing.T) {
	payloads := GetDefaultPayloads()
	if len(payloads) == 0 {
		t.Error("Expected default payloads, got 0")
	}

	if len(payloads) < 50 {
		t.Errorf("Expected at least 50 payloads, got %d", len(payloads))
	}

	for _, p := range payloads {
		if p.Name == "" || p.Content == "" || p.Type == "" {
			t.Errorf("Invalid payload found: %+v", p)
		}
	}
}
