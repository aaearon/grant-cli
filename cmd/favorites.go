package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/config"
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

// NewFavoritesCommandWithAllDeps creates the favorites command with all injected dependencies including groups
func NewFavoritesCommandWithAllDeps(eligLister eligibilityLister, sel unifiedSelector, prompter namePrompter, groupsElig groupsEligibilityLister) *cobra.Command {
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
		return runFavoritesAddWithDeps(c, args, eligLister, sel, prompter, nil, groupsElig)
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

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws (omit to show all)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().String("type", "", "Favorite type: cloud, groups (default: cloud)")
	cmd.Flags().StringP("group", "g", "", "Group name (for --type groups)")

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

	// Validate: target and role must both be provided or both omitted
	if (target != "" && role == "") || (target == "" && role != "") {
		return errors.New("both --target and --role must be provided")
	}

	favType, _ := cmd.Flags().GetString("type")
	group, _ := cmd.Flags().GetString("group")

	if favType == config.FavoriteTypeGroups {
		if group != "" {
			// Non-interactive groups mode: no auth needed
			return runFavoritesAddWithDeps(cmd, args, nil, nil, nil, nil, nil)
		}
	} else if target != "" && role != "" {
		// Non-interactive cloud mode: no auth needed
		return runFavoritesAddWithDeps(cmd, args, nil, nil, nil, nil, nil)
	}

	// Interactive path: load config early for fast-fail duplicate check
	cfg, _, err := config.LoadDefaultWithPath()
	if err != nil {
		return err
	}

	if len(args) > 0 {
		if _, err := config.GetFavorite(cfg, args[0]); err == nil {
			return fmt.Errorf("favorite %q already exists", args[0])
		}
	}

	// Bootstrap auth and SCA service
	_, scaService, _, err := bootstrapSCAService()
	if err != nil {
		return err
	}

	cachedLister := buildCachedLister(cfg, false, scaService, scaService)

	return runFavoritesAddWithDeps(cmd, args, cachedLister, &uiUnifiedSelector{}, &surveyNamePrompter{}, cfg, cachedLister)
}

// favoritesAddFlags holds the parsed flags for the favorites add command.
type favoritesAddFlags struct {
	provider string
	target   string
	role     string
	favType  string
	group    string
}

// parseFavoritesAddFlags reads and validates the flags for favorites add.
func parseFavoritesAddFlags(cmd *cobra.Command) (*favoritesAddFlags, error) {
	f := &favoritesAddFlags{}
	f.provider, _ = cmd.Flags().GetString("provider")
	f.target, _ = cmd.Flags().GetString("target")
	f.role, _ = cmd.Flags().GetString("role")
	f.favType, _ = cmd.Flags().GetString("type")
	f.group, _ = cmd.Flags().GetString("group")

	if f.favType != "" && f.favType != config.FavoriteTypeCloud && f.favType != config.FavoriteTypeGroups {
		return nil, fmt.Errorf("invalid --type %q: must be one of: cloud, groups", f.favType)
	}

	if f.favType == config.FavoriteTypeGroups {
		if f.target != "" || f.role != "" {
			return nil, errors.New("--target and --role cannot be used with --type groups")
		}
	} else {
		if f.group != "" {
			return nil, errors.New("--group requires --type groups")
		}
		if (f.target != "" && f.role == "") || (f.target == "" && f.role != "") {
			return nil, errors.New("both --target and --role must be provided")
		}
	}

	return f, nil
}

// selectFavoriteInteractive presents a unified selector and returns the chosen favorite and name.
func selectFavoriteInteractive(provider string, eligLister eligibilityLister, groupsElig groupsEligibilityLister, sel unifiedSelector, prompter namePrompter, name string, cfg *config.Config) (config.Favorite, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	allTargets, err := fetchEligibility(ctx, eligLister, provider)
	if err != nil {
		return config.Favorite{}, "", err
	}

	var items []selectionItem
	for i := range allTargets {
		items = append(items, selectionItem{kind: selectionCloud, cloud: &allTargets[i]})
	}

	if groupsElig != nil {
		groups, gErr := fetchGroupsEligibility(ctx, groupsElig, eligLister)
		if gErr == nil {
			for i := range groups {
				items = append(items, selectionItem{kind: selectionGroup, group: &groups[i]})
			}
		}
	}

	if len(items) == 0 {
		return config.Favorite{}, "", errors.New("no eligible targets or groups found")
	}

	selected, err := sel.SelectItem(items)
	if err != nil {
		return config.Favorite{}, "", fmt.Errorf("selection failed: %w", err)
	}

	var fav config.Favorite
	switch selected.kind {
	case selectionCloud:
		resolveTargetCSP(selected.cloud, allTargets, provider)
		if provider != "" {
			fav.Provider = provider
		} else {
			fav.Provider = strings.ToLower(string(selected.cloud.CSP))
		}
		fav.Target = selected.cloud.WorkspaceName
		fav.Role = selected.cloud.RoleInfo.Name
	case selectionGroup:
		fav.Type = config.FavoriteTypeGroups
		fav.Provider = "azure"
		fav.Group = selected.group.GroupName
		fav.DirectoryID = selected.group.DirectoryID
	}

	if name == "" {
		name, err = prompter.PromptName()
		if err != nil {
			return config.Favorite{}, "", fmt.Errorf("failed to read favorite name: %w", err)
		}
		if _, err := config.GetFavorite(cfg, name); err == nil {
			return config.Favorite{}, "", fmt.Errorf("favorite %q already exists", name)
		}
	}

	return fav, name, nil
}

// runFavoritesAddWithDeps contains the core logic for favorites add.
// When eligLister and sel are nil, it uses the non-interactive flag path.
// If preloadedCfg is non-nil, it is used instead of loading from disk.
func runFavoritesAddWithDeps(cmd *cobra.Command, args []string, eligLister eligibilityLister, sel unifiedSelector, prompter namePrompter, preloadedCfg *config.Config, groupsElig groupsEligibilityLister) error {
	f, err := parseFavoritesAddFlags(cmd)
	if err != nil {
		return err
	}

	// Determine name from arg
	var name string
	if len(args) > 0 {
		name = args[0]
	}

	// Non-interactive mode requires name upfront
	isNonInteractive := (f.target != "" && f.role != "") || (f.favType == config.FavoriteTypeGroups && f.group != "")
	if isNonInteractive {
		log.Info("Non-interactive mode: target=%q role=%q provider=%q group=%q", f.target, f.role, f.provider, f.group)
	}
	if isNonInteractive && name == "" {
		if f.favType == config.FavoriteTypeGroups {
			return errors.New("name is required when using --group flag\n\nUsage:\n  grant favorites add <name> --type groups --group <group>")
		}
		return errors.New("name is required when using --target and --role flags\n\nUsage:\n  grant favorites add <name> --target <target> --role <role>")
	}

	// Load config (skip if pre-loaded)
	var cfg *config.Config
	var cfgPath string
	if preloadedCfg != nil {
		cfg = preloadedCfg
		cfgPath, _ = config.ConfigPath()
	} else {
		cfg, cfgPath, err = config.LoadDefaultWithPath()
		if err != nil {
			return err
		}
	}

	// Check duplicate early if name is already known
	if name != "" {
		if _, err := config.GetFavorite(cfg, name); err == nil {
			return fmt.Errorf("favorite %q already exists", name)
		}
	}

	// Groups flow
	if f.favType == config.FavoriteTypeGroups {
		return addGroupFavorite(cmd, name, f.group, cfg, cfgPath, groupsElig, eligLister, sel, prompter)
	}

	// Cloud flow
	var fav config.Favorite
	if f.target != "" && f.role != "" {
		fav.Target = f.target
		fav.Role = f.role
		fav.Provider = f.provider
		if fav.Provider == "" {
			fav.Provider = cfg.DefaultProvider
		}
	} else {
		fav, name, err = selectFavoriteInteractive(f.provider, eligLister, groupsElig, sel, prompter, name, cfg)
		if err != nil {
			return err
		}
	}

	log.Info("Saving favorite %q...", name)
	if err := config.AddFavorite(cfg, name, fav); err != nil {
		return fmt.Errorf("failed to add favorite: %w", err)
	}
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	if fav.ResolvedType() == config.FavoriteTypeGroups {
		fmt.Fprintf(cmd.OutOrStdout(), "Added favorite %q: groups/%s\n", name, fav.Group)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Added favorite %q: %s/%s/%s\n", name, fav.Provider, fav.Target, fav.Role)
	}
	return nil
}

// addGroupFavorite handles the --type groups flow for favorites add.
func addGroupFavorite(cmd *cobra.Command, name, group string, cfg *config.Config, cfgPath string, groupsElig groupsEligibilityLister, eligLister eligibilityLister, sel unifiedSelector, prompter namePrompter) error {
	var fav config.Favorite
	fav.Type = config.FavoriteTypeGroups
	fav.Provider = "azure"

	if group != "" {
		// Non-interactive: group specified via flag
		fav.Group = group
	} else {
		// Interactive: select from eligible groups via unified selector
		ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
		defer cancel()

		groups, err := fetchGroupsEligibility(ctx, groupsElig, eligLister)
		if err != nil {
			return err
		}

		var items []selectionItem
		for i := range groups {
			items = append(items, selectionItem{kind: selectionGroup, group: &groups[i]})
		}

		selected, err := sel.SelectItem(items)
		if err != nil {
			return fmt.Errorf("group selection failed: %w", err)
		}

		fav.Group = selected.group.GroupName
		fav.DirectoryID = selected.group.DirectoryID

		if name == "" {
			name, err = prompter.PromptName()
			if err != nil {
				return fmt.Errorf("failed to read favorite name: %w", err)
			}
			if _, err := config.GetFavorite(cfg, name); err == nil {
				return fmt.Errorf("favorite %q already exists", name)
			}
		}
	}

	if err := config.AddFavorite(cfg, name, fav); err != nil {
		return fmt.Errorf("failed to add favorite: %w", err)
	}
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Added favorite %q: groups/%s\n", name, fav.Group)
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
				return errors.New("requires a favorite name\n\nUsage:\n  grant favorites remove <name>\n\nSee available favorites with 'grant favorites list'")
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
	log.Info("Loading config...")
	cfg, _, err := config.LoadDefaultWithPath()
	if err != nil {
		return err
	}

	// List favorites
	favorites := config.ListFavorites(cfg)
	log.Info("Found %d favorite(s)", len(favorites))
	if len(favorites) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No favorites saved. Run 'grant favorites add' to create one.")
		return nil
	}

	for _, entry := range favorites {
		if entry.ResolvedType() == config.FavoriteTypeGroups {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: groups/%s\n", entry.Name, entry.Group)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s/%s/%s\n", entry.Name, entry.Provider, entry.Target, entry.Role)
		}
	}

	return nil
}

func runFavoritesRemove(cmd *cobra.Command, args []string) error {
	name := args[0]

	log.Info("Loading config...")
	cfg, cfgPath, err := config.LoadDefaultWithPath()
	if err != nil {
		return err
	}

	// Remove favorite
	log.Info("Removing favorite %q", name)
	if err := config.RemoveFavorite(cfg, name); err != nil {
		return err
	}

	// Save config
	log.Info("Saving config...")
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removed favorite %q\n", name)
	return nil
}
