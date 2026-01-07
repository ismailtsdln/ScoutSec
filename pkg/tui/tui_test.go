package tui

import (
	"testing"
)

func TestNewModel(t *testing.T) {
	target := "https://example.com"
	m := NewModel(target)

	if m.Target != target {
		t.Errorf("Expected target %s, got %s", target, m.Target)
	}

	if len(m.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(m.Findings))
	}

	if m.Done {
		t.Error("Expected Done to be false")
	}

	if m.Progress != 0 {
		t.Errorf("Expected progress 0, got %f", m.Progress)
	}
}

func TestGetSeverityStyle(t *testing.T) {
	// Just verify no panics
	_ = getSeverityStyle("Critical")
	_ = getSeverityStyle("High")
	_ = getSeverityStyle("Medium")
	_ = getSeverityStyle("Low")
	_ = getSeverityStyle("Info")
	_ = getSeverityStyle("Unknown")
}
