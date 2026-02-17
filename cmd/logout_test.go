package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestLogoutCommand(t *testing.T) {
	tests := []struct {
		name        string
		clearer     keyringClearer
		wantContain []string
		wantErr     bool
	}{
		{
			name:    "successful logout",
			clearer: &mockKeyringClearer{},
			wantContain: []string{
				"Logged out successfully",
			},
			wantErr: false,
		},
		{
			name: "keyring clear error",
			clearer: &mockKeyringClearer{
				clearErr: errors.New("keyring unavailable"),
			},
			wantContain: []string{
				"failed to clear authentication",
				"keyring unavailable",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewLogoutCommandWithDeps(tt.clearer)

			output, err := executeCommand(cmd)

			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestLogoutCommandIntegration(t *testing.T) {
	// Test that logout command is properly registered
	rootCmd := newTestRootCommand()
	logoutCmd := NewLogoutCommandWithDeps(&mockKeyringClearer{})
	rootCmd.AddCommand(logoutCmd)

	output, err := executeCommand(rootCmd, "logout")
	if err != nil {
		t.Fatalf("logout command failed: %v", err)
	}

	if !strings.Contains(output, "Logged out successfully") {
		t.Errorf("expected success message, got: %s", output)
	}
}

func TestLogoutCommandHelp(t *testing.T) {
	cmd := NewLogoutCommand()

	output, err := executeCommand(cmd, "--help")
	if err != nil {
		t.Fatalf("help command failed: %v", err)
	}

	expectedStrings := []string{
		"logout",
		"clearing cached authentication tokens",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("help output missing %q\ngot:\n%s", expected, output)
		}
	}
}

func TestLogoutCommandStructure(t *testing.T) {
	cmd := NewLogoutCommand()

	if cmd.Use != "logout" {
		t.Errorf("expected Use to be 'logout', got: %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE function should be defined")
	}
}
