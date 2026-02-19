package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

func TestUpdateCommand(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		updater     *mockSelfUpdater
		wantErr     bool
		wantContain []string
	}{
		{
			name:    "dev build returns error",
			version: "",
			updater: &mockSelfUpdater{},
			wantErr: true,
			wantContain: []string{
				"cannot update a dev build",
			},
		},
		{
			name:    "explicit dev version returns error",
			version: "dev",
			updater: &mockSelfUpdater{},
			wantErr: true,
			wantContain: []string{
				"cannot update a dev build",
			},
		},
		{
			name:    "already up to date",
			version: "1.0.0",
			updater: &mockSelfUpdater{
				release: &selfupdate.Release{
					Version: semver.MustParse("1.0.0"),
				},
			},
			wantErr: false,
			wantContain: []string{
				"already up to date",
				"1.0.0",
			},
		},
		{
			name:    "successful update",
			version: "1.0.0",
			updater: &mockSelfUpdater{
				release: &selfupdate.Release{
					Version: semver.MustParse("1.1.0"),
				},
			},
			wantErr: false,
			wantContain: []string{
				"1.0.0",
				"1.1.0",
			},
		},
		{
			name:    "api error propagated",
			version: "1.0.0",
			updater: &mockSelfUpdater{
				updateErr: errors.New("rate limit exceeded"),
			},
			wantErr: true,
			wantContain: []string{
				"update failed",
				"rate limit exceeded",
			},
		},
		{
			name:    "nil release without error",
			version: "1.0.0",
			updater: &mockSelfUpdater{},
			wantErr: true,
			wantContain: []string{
				"no release information",
			},
		},
		{
			name:    "version with v prefix",
			version: "v2.0.0",
			updater: &mockSelfUpdater{
				release: &selfupdate.Release{
					Version: semver.MustParse("2.0.0"),
				},
			},
			wantErr: false,
			wantContain: []string{
				"already up to date",
				"2.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldVersion := version
			version = tt.version
			defer func() { version = oldVersion }()

			cmd := NewUpdateCommandWithDeps(tt.updater)
			output, err := executeCommand(cmd)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestUpdateCommandPassesSlug(t *testing.T) {
	oldVersion := version
	version = "1.0.0"
	defer func() { version = oldVersion }()

	var gotSlug string
	updater := &mockSelfUpdater{
		updateSelfFn: func(v semver.Version, slug string) (*selfupdate.Release, error) {
			gotSlug = slug
			return &selfupdate.Release{Version: v}, nil
		},
	}

	cmd := NewUpdateCommandWithDeps(updater)
	_, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotSlug != "aaearon/grant-cli" {
		t.Errorf("expected slug %q, got %q", "aaearon/grant-cli", gotSlug)
	}
}

func TestUpdateCommand_VerboseLogs(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	oldVersion := version
	version = "1.0.0"
	defer func() { version = oldVersion }()

	updater := &mockSelfUpdater{
		release: &selfupdate.Release{
			Version: semver.MustParse("1.1.0"),
		},
	}

	cmd := NewUpdateCommandWithDeps(updater)
	_, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantMessages := []string{
		"Current version: 1.0.0",
		"Checking for updates",
		updateSlug,
	}

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

func TestUpdateCommandIntegration(t *testing.T) {
	rootCmd := newTestRootCommand()
	updateCmd := NewUpdateCommandWithDeps(&mockSelfUpdater{
		release: &selfupdate.Release{
			Version: semver.MustParse("0.0.1"),
		},
	})
	rootCmd.AddCommand(updateCmd)

	oldVersion := version
	version = "0.0.1"
	defer func() { version = oldVersion }()

	output, err := executeCommand(rootCmd, "update")
	if err != nil {
		t.Fatalf("update command failed: %v", err)
	}

	if !strings.Contains(output, "already up to date") {
		t.Errorf("expected 'already up to date', got: %s", output)
	}
}
