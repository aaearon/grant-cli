package cmd

import (
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		commit      string
		date        string
		wantContain []string
	}{
		{
			name:    "dev build without ldflags",
			version: "",
			commit:  "",
			date:    "",
			wantContain: []string{
				"grant version dev",
				"commit: unknown",
				"built: unknown",
			},
		},
		{
			name:    "release build with ldflags",
			version: "1.0.0",
			commit:  "abc1234",
			date:    "2026-02-10T12:00:00Z",
			wantContain: []string{
				"grant version 1.0.0",
				"commit: abc1234",
				"built: 2026-02-10T12:00:00Z",
			},
		},
		{
			name:    "partial ldflags - version only",
			version: "1.0.0",
			commit:  "",
			date:    "",
			wantContain: []string{
				"grant version 1.0.0",
				"commit: unknown",
				"built: unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global variables
			oldVersion, oldCommit, oldDate := version, commit, buildDate
			version, commit, buildDate = tt.version, tt.commit, tt.date
			defer func() {
				version, commit, buildDate = oldVersion, oldCommit, oldDate
			}()

			// Capture output
			cmd := NewVersionCommand()
			output, err := executeCommand(cmd)
			if err != nil {
				t.Fatalf("command failed: %v", err)
			}

			// Verify all expected strings are present
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestVersionCommand_VerboseLogs(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	oldVersion, oldCommit, oldDate := version, commit, buildDate
	version, commit, buildDate = "1.0.0", "abc1234", "2026-02-10"
	defer func() { version, commit, buildDate = oldVersion, oldCommit, oldDate }()

	cmd := NewVersionCommand()
	_, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantMessages := []string{"Go version", "OS/Arch"}
	for _, want := range wantMessages {
		found := false
		for _, msg := range spy.messages {
			if strings.Contains(msg, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected log containing %q, got: %v", want, spy.messages)
		}
	}
}

func TestVersionCommandIntegration(t *testing.T) {
	// Test that version command is properly registered
	rootCmd := newTestRootCommand()
	versionCmd := NewVersionCommand()
	rootCmd.AddCommand(versionCmd)

	// Execute version command
	output, err := executeCommand(rootCmd, "version")
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	// Should contain at least the version line
	if !strings.Contains(output, "grant version") {
		t.Errorf("version output missing 'grant version', got: %s", output)
	}
}
