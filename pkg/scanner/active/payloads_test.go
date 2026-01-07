package active

import (
	"testing"
)

func TestGetDefaultPayloads(t *testing.T) {
	payloads := GetDefaultPayloads()
	if len(payloads) == 0 {
		t.Error("Expected default payloads, got 0")
	}

	for _, p := range payloads {
		if p.Name == "" || p.Content == "" || p.Type == "" {
			t.Errorf("Invalid payload found: %+v", p)
		}
	}
}
