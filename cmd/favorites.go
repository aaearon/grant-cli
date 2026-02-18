package cmd

import (
	"context"
	"fmt"
	"strings"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/spf13/cobra"
)

// NewFavoritesCommand creates the favorites parent command with subcommands
func NewFavoritesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "favorites",
		Short: "Manage saved elevation favorites",
		Long: `Add, list, and remove saved elevation target favorites for quick access.

Favorites let you save frequently-used elevation targets so you can
elevate with a single command: grant --favorite <name>

Workflow:
  1. grant favorites add         # select a target and save it
  2. grant favorites list        # see your saved favorites
  3. grant --favorite <name>     # elevate using the favorite`,
	}

	cmd.AddCommand(newFavoritesAddCommand())
	cmd.AddCommand(newFavoritesListCommand())
	cmd.AddCommand(newFavoritesRemoveCommand())

	return cmd
}

// NewFavoritesCommandWithDeps creates the favorites command with injected dependencies for testing
func NewFavoritesCommandWithDeps(eligLister eligibilityLister, sel targetSelector, prompter namePrompter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "favorites",
		Short: "Manage saved elevation favorites",
		Long: `Add, list, and remove saved elevation target favorites for quick access.

Favorites let you save frequently-used elevation targets so you can
elevate with a single command: grant --favorite <name>

Workflow:
  1. grant favorites add         # select a target and save it
  2. grant favorites list        # see your saved favorites
  3. grant --favorite <name>     # elevate using the favorite`,
	}

	cmd.AddCommand(newFavoritesAddCommandWithRunner(func(c *cobra.Command, args []string) error {
		return runFavoritesAddWithDeps(c, args, eligLister, sel, prompter)
	}))
	cmd.AddCommand(newFavoritesListCommand())
	cmd.AddCommand(newFavoritesRemoveCommand())

	return cmd
}

// newFavoritesAddCommandWithRunner creates the add command with a custom RunE function.
// All flag registration is centralized here.
func newFavoritesAddCommandWithRunner(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new favorite",
		Long:  "Add a new elevation target as a favorite, either by selecting from eligible targets or via --target and --role flags.",
		Example: `  # Interactive: select target, then name the favorite
  grant favorites add

  # Interactive with name upfront
  grant favorites add prod-admin

  # Non-interactive: specify target and role directly
  grant favorites add prod-admin --target "Prod-EastUS" --role "Contributor"`,
		Args: cobra.RangeArgs(0, 1),
		RunE: runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider (default from config, v1: azure only)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")

	return cmd
}

func newFavoritesAddCommand() *cobra.Command {
	return newFavoritesAddCommandWithRunner(runFavoritesAddProduction)
}

// surveyNamePrompter implements namePrompter using survey for interactive prompts
type surveyNamePrompter struct{}

func (s *surveyNamePrompter) PromptName() (string, error) {
	var name string
	if err := survey.AskOne(&survey.Input{
		Message: "Favorite name:",
	}, &name, survey.WithValidator(survey.Required)); err != nil {
		return "", err
	}
	return name, nil
}

// runFavoritesAddProduction is the production RunE for favorites add.
// It handles auth bootstrapping for interactive mode and delegates to runFavoritesAddWithDeps.
func runFavoritesAddProduction(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	role, _ := cmd.Flags().GetString("role")

	if target != "" && role != "" {
		// Non-interactive: no auth needed
		return runFavoritesAddWithDeps(cmd, args, nil, nil, nil)
	}

	// Validate: partial flags are always an error (fast fail before auth)
	if (target != "" && role == "") || (target == "" && role != "") {
		return fmt.Errorf("both --target and --role must be provided")
	}

	// Interactive path: check duplicate before auth (fast fail) if name was provided
	if len(args) > 0 {
		name := args[0]
		cfgPath, err := config.ConfigPath()
		if err != nil {
			return fmt.Errorf("failed to determine config path: %w", err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if _, err := config.GetFavorite(cfg, name); err == nil {
			return fmt.Errorf("favorite %q already exists", name)
		}
	}

	// Bootstrap auth and SCA service
	_, scaService, _, err := bootstrapSCAService()
	if err != nil {
		return err
	}

	return runFavoritesAddWithDeps(cmd, args, scaService, &uiSelector{}, &surveyNamePrompter{})
}

// runFavoritesAddWithDeps contains the core logic for favorites add.
// When eligLister and sel are nil, it uses the non-interactive flag path.
func runFavoritesAddWithDeps(cmd *cobra.Command, args []string, eligLister eligibilityLister, sel targetSelector, prompter namePrompter) error {
	// Read flags
	provider, _ := cmd.Flags().GetString("provider")
	target, _ := cmd.Flags().GetString("target")
	role, _ := cmd.Flags().GetString("role")

	// Validate: target and role must both be provided or both omitted
	if (target != "" && role == "") || (target == "" && role != "") {
		return fmt.Errorf("both --target and --role must be provided")
	}

	// Determine name from arg (may be empty for interactive prompt-after-selection)
	var name string
	if len(args) > 0 {
		name = args[0]
	}

	// Non-interactive mode requires name upfront
	if target != "" && role != "" && name == "" {
		return fmt.Errorf("name is required when using --target and --role flags\n\nUsage:\n  grant favorites add <name> --target <target> --role <role>")
	}

	// Load config
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check duplicate early if name is already known
	if name != "" {
		if _, err := config.GetFavorite(cfg, name); err == nil {
			return fmt.Errorf("favorite %q already exists", name)
		}
	}

	var fav config.Favorite

	if target != "" && role != "" {
		// Non-interactive mode: use flags directly
		fav.Target = target
		fav.Role = role
		fav.Provider = provider
		if fav.Provider == "" {
			fav.Provider = cfg.DefaultProvider
		}
	} else {
		// Interactive mode: select from eligible targets
		if provider == "" {
			provider = cfg.DefaultProvider
		}

		// Validate provider (v1 only accepts azure)
		if strings.ToLower(provider) != "azure" {
			return fmt.Errorf("provider %q is not supported in this version, supported providers: azure", provider)
		}

		csp := models.CSP(strings.ToUpper(provider))
		ctx := context.Background()

		// Fetch eligibility
		eligibilityResp, err := eligLister.ListEligibility(ctx, csp)
		if err != nil {
			return fmt.Errorf("failed to fetch eligible targets: %w", err)
		}

		if len(eligibilityResp.Response) == 0 {
			return fmt.Errorf("no eligible %s targets found, check your SCA policies", strings.ToLower(provider))
		}

		// Interactive selection
		selectedTarget, err := sel.SelectTarget(eligibilityResp.Response)
		if err != nil {
			return fmt.Errorf("target selection failed: %w", err)
		}

		fav.Provider = provider
		fav.Target = selectedTarget.WorkspaceName
		fav.Role = selectedTarget.RoleInfo.Name

		// Prompt for name after selection if not provided
		if name == "" {
			name, err = prompter.PromptName()
			if err != nil {
				return fmt.Errorf("failed to read favorite name: %w", err)
			}

			// Check duplicate for prompted name
			if _, err := config.GetFavorite(cfg, name); err == nil {
				return fmt.Errorf("favorite %q already exists", name)
			}
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

func newFavoritesListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all favorites",
		Long:    "Display all saved elevation target favorites.",
		Example: "  grant favorites list",
		Args:    cobra.NoArgs,
		RunE:    runFavoritesList,
	}
}

func newFavoritesRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   "Remove a favorite",
		Long:    "Remove a saved elevation target favorite by name.",
		Example: "  grant favorites remove prod-admin",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("requires a favorite name\n\nUsage:\n  grant favorites remove <name>\n\nSee available favorites with 'grant favorites list'")
			}
			if len(args) > 1 {
				return fmt.Errorf("expected 1 favorite name, got %d", len(args))
			}
			return nil
		},
		RunE: runFavoritesRemove,
	}
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
		fmt.Fprintln(cmd.OutOrStdout(), "No favorites saved. Run 'grant favorites add' to create one.")
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
