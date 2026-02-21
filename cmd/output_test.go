package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIsJSONOutput(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   bool
	}{
		{"text format", "text", false},
		{"json format", "json", true},
		{"empty format", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := outputFormat
			defer func() { outputFormat = old }()

			outputFormat = tt.format
			if got := isJSONOutput(); got != tt.want {
				t.Errorf("isJSONOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	type sample struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	var buf bytes.Buffer
	err := writeJSON(&buf, sample{Name: "test", Count: 42})
	if err != nil {
		t.Fatalf("writeJSON() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot: %s", err, buf.String())
	}

	if parsed["name"] != "test" {
		t.Errorf("expected name=test, got %v", parsed["name"])
	}
	if parsed["count"] != float64(42) {
		t.Errorf("expected count=42, got %v", parsed["count"])
	}
}
