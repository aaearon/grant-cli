package cmd

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
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

	flags := []string{"verbose", "provider", "target", "role", "favorite"}
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
