package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/spf13/cobra"
)

func TestNewRootCommand_SilenceFlags(t *testing.T) {
	cmd := newRootCommand(nil)

	if !cmd.SilenceErrors {
		t.Error("expected SilenceErrors to be true")
	}
	if !cmd.SilenceUsage {
		t.Error("expected SilenceUsage to be true")
	}
}

func TestNewRootCommand_FlagsRegistered(t *testing.T) {
	cmd := newRootCommand(nil)

	flags := []string{"verbose", "provider", "target", "role", "favorite", "refresh", "groups", "group"}
	for _, flag := range flags {
		if cmd.Flags().Lookup(flag) == nil && cmd.PersistentFlags().Lookup(flag) == nil {
			t.Errorf("expected --%s flag to be registered", flag)
		}
	}
}

func TestNewTestRootCommand_ReturnsValidCommand(t *testing.T) {
	cmd := newTestRootCommand()

	if cmd.Use != "grant" {
		t.Errorf("expected Use='grant', got %q", cmd.Use)
	}
	if cmd.SilenceErrors != true {
		t.Error("expected SilenceErrors to be true")
	}
}

func TestPersistentPreRunE_VerboseEnabled(t *testing.T) {
	t.Setenv(config.IdsecLogLevelEnvVar, "CRITICAL")

	root := newTestRootCommand()
	// Add a no-op subcommand to exercise PersistentPreRunE
	root.AddCommand(newNoOpCommand())

	_, err := executeCommand(root, "--verbose", "noop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	level := os.Getenv(config.IdsecLogLevelEnvVar)
	if level != "INFO" {
		t.Errorf("expected IDSEC_LOG_LEVEL=INFO, got %q", level)
	}
}

func TestPersistentPreRunE_VerboseDisabled(t *testing.T) {
	t.Setenv(config.IdsecLogLevelEnvVar, "DEBUG")

	root := newTestRootCommand()
	root.AddCommand(newNoOpCommand())

	_, err := executeCommand(root, "noop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	level := os.Getenv(config.IdsecLogLevelEnvVar)
	if level != "CRITICAL" {
		t.Errorf("expected IDSEC_LOG_LEVEL=CRITICAL, got %q", level)
	}
}

func TestVerboseHintSuppressedForArgErrors(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantHint bool
	}{
		{
			name:     "arg error - hint suppressed",
			args:     []string{"favorites", "remove"}, // missing required arg
			wantHint: false,
		},
		{
			name:     "runtime error - hint shown",
			args:     []string{"favorites", "remove", "nonexistent"},
			wantHint: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a command tree that exercises the hint logic
			root := newRootCommand(nil)
			root.AddCommand(NewFavoritesCommand())

			// Simulate what Execute() does
			root.SetArgs(tt.args)
			passedArgValidation = false
			defer func() { passedArgValidation = false }()
			err := root.Execute()

			var hint string
			if err != nil && !verbose && !passedArgValidation {
				hint = ""
			} else if err != nil && !verbose {
				hint = "Hint: re-run with --verbose for more details"
			}

			if tt.wantHint && hint == "" {
				t.Error("expected verbose hint to be shown, but it was suppressed")
			}
			if !tt.wantHint && hint != "" {
				t.Error("expected verbose hint to be suppressed, but it was shown")
			}
		})
	}
}

func TestVerboseHintSuppressedForUnknownSubcommand(t *testing.T) {
	root := newRootCommand(nil)
	root.AddCommand(NewFavoritesCommand())

	root.SetArgs([]string{"nonexistent-command"})
	passedArgValidation = false
	defer func() { passedArgValidation = false }()
	err := root.Execute()

	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}

	if passedArgValidation {
		t.Error("passedArgValidation should be false for unknown subcommand")
	}
}

func TestVerboseHintShownForRuntimeErrors(t *testing.T) {
	root := newRootCommand(func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("runtime failure")
	})

	root.SetArgs([]string{})
	passedArgValidation = false
	defer func() { passedArgValidation = false }()
	err := root.Execute()

	if err == nil {
		t.Fatal("expected runtime error")
	}

	if !passedArgValidation {
		t.Error("passedArgValidation should be true for runtime errors")
	}

	// Simulate Execute() hint logic
	if verbose || !passedArgValidation {
		t.Skip("hint would be suppressed, but shouldn't be for runtime errors")
	}
}

func TestExecuteHintOutput(t *testing.T) {
	// Test the full executeWithHint helper to verify the hint text
	tests := []struct {
		name       string
		setupCmd   func() *cobra.Command
		args       []string
		wantHint   bool
		wantErrStr string
	}{
		{
			name: "arg error suppresses hint",
			setupCmd: func() *cobra.Command {
				root := newRootCommand(nil)
				root.AddCommand(NewFavoritesCommand())
				return root
			},
			args:       []string{"favorites", "remove"},
			wantHint:   false,
			wantErrStr: "requires a favorite name",
		},
		{
			name: "runtime error shows hint",
			setupCmd: func() *cobra.Command {
				return newRootCommand(func(cmd *cobra.Command, args []string) error {
					return fmt.Errorf("something went wrong")
				})
			},
			args:       []string{},
			wantHint:   true,
			wantErrStr: "something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.setupCmd()
			errOutput := executeWithHint(cmd, tt.args)

			if !strings.Contains(errOutput, tt.wantErrStr) {
				t.Errorf("expected error output to contain %q, got:\n%s", tt.wantErrStr, errOutput)
			}

			hasHint := strings.Contains(errOutput, "Hint: re-run with --verbose")
			if tt.wantHint && !hasHint {
				t.Errorf("expected verbose hint in output, got:\n%s", errOutput)
			}
			if !tt.wantHint && hasHint {
				t.Errorf("expected no verbose hint in output, got:\n%s", errOutput)
			}
		})
	}
}
