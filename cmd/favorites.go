package cmd

import (
	"fmt"

	"github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/spf13/cobra"
)

// NewFavoritesCommand creates the favorites parent command with subcommands
func NewFavoritesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "favorites",
		Short: "Manage saved elevation favorites",
		Long:  "Add, list, and remove saved elevation target favorites for quick access.",
	}

	cmd.AddCommand(newFavoritesAddCommand())
	cmd.AddCommand(newFavoritesListCommand())
	cmd.AddCommand(newFavoritesRemoveCommand())

	return cmd
}

func newFavoritesAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new favorite",
		Long:  "Add a new elevation target as a favorite, either interactively or via --target and --role flags.",
		Args:  cobra.ExactArgs(1),
		RunE:  runFavoritesAdd,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider (default from config, v1: azure only)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")

	return cmd
}

func newFavoritesListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all favorites",
		Long:  "Display all saved elevation target favorites.",
		Args:  cobra.NoArgs,
		RunE:  runFavoritesList,
	}
}

func newFavoritesRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a favorite",
		Long:  "Remove a saved elevation target favorite by name.",
		Args:  cobra.ExactArgs(1),
		RunE:  runFavoritesRemove,
	}
}

func runFavoritesAdd(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Load config
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if favorite already exists
	if _, err := config.GetFavorite(cfg, name); err == nil {
		return fmt.Errorf("favorite %q already exists", name)
	}

	// Read flags
	provider, _ := cmd.Flags().GetString("provider")
	target, _ := cmd.Flags().GetString("target")
	role, _ := cmd.Flags().GetString("role")

	// Validate: target and role must both be provided or both omitted
	if (target != "" && role == "") || (target == "" && role != "") {
		return fmt.Errorf("both --target and --role must be provided")
	}

	var fav config.Favorite

	if target != "" && role != "" {
		// Non-interactive mode: use flags
		fav.Target = target
		fav.Role = role
		fav.Provider = provider
		if fav.Provider == "" {
			fav.Provider = cfg.DefaultProvider
		}
	} else {
		// Interactive mode: survey prompts
		providerDefault := cfg.DefaultProvider
		if provider != "" {
			providerDefault = provider
		}

		providerPrompt := &survey.Input{
			Message: "Provider:",
			Default: providerDefault,
		}
		if err := survey.AskOne(providerPrompt, &fav.Provider); err != nil {
			return fmt.Errorf("provider prompt failed: %w", err)
		}

		targetPrompt := &survey.Input{
			Message: "Target (e.g., subscription ID):",
		}
		if err := survey.AskOne(targetPrompt, &fav.Target, survey.WithValidator(survey.Required)); err != nil {
			return fmt.Errorf("target prompt failed: %w", err)
		}

		rolePrompt := &survey.Input{
			Message: "Role (e.g., Contributor, Reader):",
		}
		if err := survey.AskOne(rolePrompt, &fav.Role, survey.WithValidator(survey.Required)); err != nil {
			return fmt.Errorf("role prompt failed: %w", err)
		}
	}

	// Add favorite
	if err := config.AddFavorite(cfg, name, fav); err != nil {
		return fmt.Errorf("failed to add favorite: %w", err)
	}

	// Save config
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Added favorite %q: %s/%s/%s\n", name, fav.Provider, fav.Target, fav.Role)
	return nil
}

func runFavoritesList(cmd *cobra.Command, args []string) error {
	// Load config
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// List favorites
	favorites := config.ListFavorites(cfg)
	if len(favorites) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No favorites saved")
		return nil
	}

	for _, entry := range favorites {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s/%s/%s\n",
			entry.Name,
			entry.Provider,
			entry.Target,
			entry.Role)
	}

	return nil
}

func runFavoritesRemove(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Load config
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Remove favorite
	if err := config.RemoveFavorite(cfg, name); err != nil {
		return err
	}

	// Save config
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removed favorite %q\n", name)
	return nil
}

func init() {
	rootCmd.AddCommand(NewFavoritesCommand())
}
