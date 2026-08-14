package cmd

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// resetKeyringOverrideState restores the package globals this file mutates.
func resetKeyringOverrideState(t *testing.T) {
	t.Helper()
	origApply := keyringApply
	origNotice := keyringEnvNotice
	origVerbose := verbose
	origLog := log
	t.Cleanup(func() {
		keyringApply = origApply
		keyringEnvNotice = origNotice
		verbose = origVerbose
		log = origLog
	})
}

// TestExecuteWithKeyringOverrideRunsBeforeCommand proves the keyring override
// is applied at startup, before any command code executes.
func TestExecuteWithKeyringOverrideRunsBeforeCommand(t *testing.T) {
	resetKeyringOverrideState(t)

	var order []string
	keyringApply = func() (bool, string, error) {
		order = append(order, "keyring-override")
		return true, "WSL detected (test); forcing file-based keyring", nil
	}
	keyringEnvNotice = ""

	cmd := newRootCommand(func(*cobra.Command, []string) error {
		order = append(order, "command-run")
		return nil
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})

	if err := executeWithKeyringOverride(cmd); err != nil {
		t.Fatalf("executeWithKeyringOverride() error = %v", err)
	}

	want := []string{"keyring-override", "command-run"}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("execution order = %v, want %v", order, want)
	}
	if keyringEnvNotice == "" {
		t.Error("keyringEnvNotice was not stashed after the override applied")
	}
}

func TestExecuteWithKeyringOverrideFailsClosed(t *testing.T) {
	resetKeyringOverrideState(t)

	keyringApply = func() (bool, string, error) {
		return false, "", errors.New("setenv denied")
	}
	keyringEnvNotice = ""

	ran := false
	cmd := newRootCommand(func(*cobra.Command, []string) error {
		ran = true
		return nil
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})

	err := executeWithKeyringOverride(cmd)
	if err == nil {
		t.Fatal("executeWithKeyringOverride() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "setenv denied") {
		t.Errorf("error = %q, want it to wrap the underlying cause", err)
	}
	if ran {
		t.Error("command executed despite the keyring override failing; want fail-closed")
	}
}

func TestExecuteWithKeyringOverrideNoNoticeWhenNotApplied(t *testing.T) {
	resetKeyringOverrideState(t)

	keyringApply = func() (bool, string, error) { return false, "not WSL", nil }
	keyringEnvNotice = ""

	cmd := newRootCommand(func(*cobra.Command, []string) error { return nil })
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})

	if err := executeWithKeyringOverride(cmd); err != nil {
		t.Fatalf("executeWithKeyringOverride() error = %v", err)
	}
	if keyringEnvNotice != "" {
		t.Errorf("keyringEnvNotice = %q, want empty when the override was not applied", keyringEnvNotice)
	}
}

// TestKeyringNoticeIsVerboseOnly checks that the stashed notice reaches the
// logger only when --verbose is passed.
//
// Note: the spy logger records Info() calls regardless of the SDK log level, so
// gating purely on IDSEC_LOG_LEVEL would be invisible to this test. The
// implementation therefore gates the emission on the parsed --verbose flag
// itself, which is what this test asserts.
func TestKeyringNoticeIsVerboseOnly(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		notice   string
		wantLogs bool
	}{
		{name: "verbose emits the notice", args: []string{"--verbose"}, notice: "WSL detected; forcing file-based keyring", wantLogs: true},
		{name: "non-verbose stays silent", args: []string{}, notice: "WSL detected; forcing file-based keyring", wantLogs: false},
		{name: "verbose with no notice logs nothing", args: []string{"--verbose"}, notice: "", wantLogs: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetKeyringOverrideState(t)

			spy := &spyLogger{}
			log = spy
			keyringEnvNotice = tt.notice
			verbose = false

			cmd := newRootCommand(func(*cobra.Command, []string) error { return nil })
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tt.args)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			var found bool
			for _, entry := range spy.messages {
				if strings.Contains(entry, "keyring") {
					found = true
				}
			}
			if found != tt.wantLogs {
				t.Errorf("notice logged = %v, want %v (calls: %v)", found, tt.wantLogs, spy.messages)
			}
		})
	}
}
