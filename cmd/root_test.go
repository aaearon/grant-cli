package cmd

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestPersistentPreRunE_VerboseEnabled(t *testing.T) {
	t.Setenv(config.IdsecLogLevelEnvVar, "CRITICAL")

	root := NewRootCommand()
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

	root := NewRootCommand()
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
