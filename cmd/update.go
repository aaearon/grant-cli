package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aaearon/grant-cli/internal/selfupdate"
	"github.com/spf13/cobra"
)

const updateSlug = "aaearon/grant-cli"

// updateTimeout bounds the whole update: release lookup plus two downloads.
var updateTimeout = 5 * time.Minute

// NewUpdateCommand creates the update command with production dependencies
func NewUpdateCommand() *cobra.Command {
	return NewUpdateCommandWithDeps(selfupdate.New(updateSlug))
}

// NewUpdateCommandWithDeps creates the update command with injected dependencies
func NewUpdateCommandWithDeps(updater selfUpdater) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update grant to the latest version",
		Long:  "Check GitHub Releases for a newer version of grant, verify its SHA-256 checksum against checksums.txt, and replace the current binary in-place.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd, updater)
		},
	}
}

func runUpdate(cmd *cobra.Command, updater selfUpdater) error {
	v := version
	if v == "" || v == "dev" {
		return errors.New("cannot update a dev build; install a release build or download from GitHub Releases")
	}

	log.Info("Current version: %s", v)

	current := strings.TrimPrefix(v, "v")

	log.Info("Checking for updates from %s", updateSlug)

	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, updateTimeout)
	defer cancel()

	latest, updated, err := updater.UpdateSelf(ctx, current)
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}
	if latest == "" {
		return errors.New("update check returned no release information")
	}

	log.Info("Latest release: %s", latest)

	if !updated {
		fmt.Fprintf(cmd.OutOrStdout(), "grant %s is already up to date.\n", current)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Updated grant from %s to %s.\n", current, latest)
	return nil
}
