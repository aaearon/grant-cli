package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

const updateSlug = "aaearon/grant-cli"

// NewUpdateCommand creates the update command with production dependencies
func NewUpdateCommand() *cobra.Command {
	return NewUpdateCommandWithDeps(selfupdate.DefaultUpdater())
}

// NewUpdateCommandWithDeps creates the update command with injected dependencies
func NewUpdateCommandWithDeps(updater selfUpdater) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update grant to the latest version",
		Long:  "Check GitHub Releases for a newer version of grant and replace the current binary in-place.",
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

	current, err := semver.Parse(strings.TrimPrefix(v, "v"))
	if err != nil {
		return fmt.Errorf("failed to parse current version %q: %w", v, err)
	}

	log.Info("Checking for updates from %s", updateSlug)

	rel, err := updater.UpdateSelf(current, updateSlug)
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}
	if rel == nil {
		return errors.New("update check returned no release information")
	}

	log.Info("Latest release: %s", rel.Version)

	if current.Equals(rel.Version) {
		fmt.Fprintf(cmd.OutOrStdout(), "grant %s is already up to date.\n", current)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Updated grant from %s to %s.\n", current, rel.Version)
	return nil
}
