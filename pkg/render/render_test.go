// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		wantErr bool
		wantNil bool
	}{
		{"empty string defaults to terminal", "", false, false},
		{"auto defaults to terminal", "auto", false, false},
		{"terminal", "terminal", false, false},
		{"terminal_brief", "terminal_brief", false, false},
		{"markdown", "markdown", false, false},
		{"yaml", "yaml", false, false},
		{"json", "json", false, false},
		{"simple", "simple", false, false},
		{"strings", "strings", false, false},
		{"interactive", "interactive", false, false},
		{"unknown renderer", "unknown", true, true},
		{"invalid renderer", "invalid-type", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			got, err := New(tt.kind, &buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && got != nil {
				t.Errorf("New() expected nil renderer for invalid type, got %T", got)
			}

			if !tt.wantNil && got == nil {
				t.Error("New() returned nil renderer for valid type")
			}

			// Verify renderer name matches (except for invalid types)
			if !tt.wantErr && got != nil {
				name := got.Name()
				if name == "" {
					t.Error("renderer Name() returned empty string")
				}
			}
		})
	}
}

func TestRiskEmoji(t *testing.T) {
	tests := []struct {
		name  string
		score int
		want  string
	}{
		{"score 0 - low", 0, "🔵"},
		{"score 1 - low", 1, "🔵"},
		{"score 2 - medium", 2, "🟡"},
		{"score 3 - high", 3, "🛑"},
		{"score 4 - critical", 4, "😈"},
		{"negative score", -1, "🔵"},
		{"very high score", 10, "🔵"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := riskEmoji(tt.score)
			if got != tt.want {
				t.Errorf("riskEmoji(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestSerializedStatsNilReport(t *testing.T) {
	stats := serializedStats(nil, nil)
	if stats != nil {
		t.Error("serializedStats with nil report should return nil")
	}
}

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	if renderer.Name() != "JSON" {
		t.Errorf("NewJSON().Name() = %q, want %q", renderer.Name(), "JSON")
	}
}

func TestNewYAML(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	if renderer.Name() != "YAML" {
		t.Errorf("NewYAML().Name() = %q, want %q", renderer.Name(), "YAML")
	}
}

func TestNewMarkdown(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewMarkdown(&buf)

	if renderer.Name() != "Markdown" {
		t.Errorf("NewMarkdown().Name() = %q, want %q", renderer.Name(), "Markdown")
	}
}

func TestNewTerminal(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewTerminal(&buf)

	if renderer.Name() != "Terminal" {
		t.Errorf("NewTerminal().Name() = %q, want %q", renderer.Name(), "Terminal")
	}
}

func TestNewTerminalBrief(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewTerminalBrief(&buf)

	if renderer.Name() != "TerminalBrief" {
		t.Errorf("NewTerminalBrief().Name() = %q, want %q", renderer.Name(), "TerminalBrief")
	}
}

func TestNewSimple(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewSimple(&buf)

	if renderer.Name() != "Simple" {
		t.Errorf("NewSimple().Name() = %q, want %q", renderer.Name(), "Simple")
	}
}

func TestNewStringMatches(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewStringMatches(&buf)

	name := renderer.Name()
	if !strings.Contains(name, "String") {
		t.Errorf("NewStringMatches().Name() = %q, expected to contain 'String'", name)
	}
}
