package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/spf13/cobra"
)

// grantExecutablePath resolves the absolute path of the running binary. It is a
// variable so tests can pin it.
var grantExecutablePath = os.Executable

// newK8sKubeconfigCommand creates the "grant k8s kubeconfig" command.
func newK8sKubeconfigCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubeconfig",
		Short: "Generate and merge a kubeconfig for eligible clusters",
		Long: `Fetch a kubeconfig for your SCA-eligible Kubernetes clusters and merge it
into your existing kubeconfig.

The merge is additive: only entries grant owns (named grant-<provider>-<name>)
are added or replaced. Your other clusters, users and contexts are left alone,
and current-context is not changed unless you pass --set-current-context.

The file is written atomically at mode 0600, and the first merge into a
pre-existing kubeconfig leaves a <target>.grant.bak copy behind.

Examples:
  grant k8s kubeconfig                          # merge into $KUBECONFIG or ~/.kube/config
  grant k8s kubeconfig --provider aws
  grant k8s kubeconfig --file ./my-kubeconfig
  grant k8s kubeconfig --stdout                 # print, touch no file`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: aws, azure (omit for all)")
	cmd.Flags().Bool("all", false, "Generate for every supported provider (default when --provider is omitted)")
	// NOTE: named --file, not --output: --output/-o is the global text|json flag.
	cmd.Flags().String("file", "", "Write to this kubeconfig instead of $KUBECONFIG / ~/.kube/config")
	cmd.Flags().Bool("stdout", false, "Write the generated kubeconfig to stdout and touch no file")
	cmd.Flags().Bool("set-current-context", false, "Point current-context at the generated context")

	cmd.MarkFlagsMutuallyExclusive("stdout", "file")
	cmd.MarkFlagsMutuallyExclusive("stdout", "set-current-context")
	cmd.MarkFlagsMutuallyExclusive("provider", "all")

	return cmd
}

// NewK8sKubeconfigCommand creates the production kubeconfig command.
func NewK8sKubeconfigCommand() *cobra.Command {
	return newK8sKubeconfigCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, _, err := bootstrapISPAuth()
		if err != nil {
			return err
		}
		svc, err := bootstrapK8sService()
		if err != nil {
			return err
		}
		return runK8sKubeconfig(cmd, ispAuth, svc)
	})
}

// kubeconfigFlags holds the parsed command-line flags.
type kubeconfigFlags struct {
	provider          string
	file              string
	toStdout          bool
	setCurrentContext bool
}

func parseKubeconfigFlags(cmd *cobra.Command) kubeconfigFlags {
	var f kubeconfigFlags
	f.provider, _ = cmd.Flags().GetString("provider")
	f.provider = strings.ToLower(strings.TrimSpace(f.provider))
	f.file, _ = cmd.Flags().GetString("file")
	f.toStdout, _ = cmd.Flags().GetBool("stdout")
	f.setCurrentContext, _ = cmd.Flags().GetBool("set-current-context")
	return f
}

// runK8sKubeconfig generates kubeconfigs and merges or prints them.
func runK8sKubeconfig(cmd *cobra.Command, auth authLoader, generator kubeconfigGenerator) error {
	if _, err := auth.LoadAuthentication(nil, true); err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	flags := parseKubeconfigFlags(cmd)

	csps := k8s.SupportedCSPs
	if flags.provider != "" {
		if _, err := k8s.NormalizeCSP(flags.provider); err != nil {
			return err
		}
		csps = []string{flags.provider}
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	generated, failures, err := generator.GenerateKubeconfigs(ctx, csps)
	if err != nil {
		return err
	}
	if len(generated) == 0 {
		return fmt.Errorf("no kubeconfig could be generated: %s", describeKubeconfigFailures(failures))
	}

	merged, rewrites, err := buildMergedKubeconfig(generated)
	if err != nil {
		return err
	}

	if flags.toStdout {
		data, err := merged.doc.Bytes()
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(data)
		return err
	}

	return writeMergedKubeconfig(cmd, flags, merged, rewrites, failures)
}

// mergedKubeconfig carries a freshly built grant-owned kubeconfig.
type mergedKubeconfig struct {
	doc      *k8s.Kubeconfig
	contexts []string
}

// buildMergedKubeconfig prefixes, rewrites and combines the per-provider
// kubeconfigs into a single grant-owned document.
func buildMergedKubeconfig(generated map[string]string) (*mergedKubeconfig, []k8s.ExecRewrite, error) {
	execPath, err := grantExecutablePath()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve the grant binary path: %w", err)
	}

	combined, err := k8s.ParseKubeconfig(nil)
	if err != nil {
		return nil, nil, err
	}

	var rewrites []k8s.ExecRewrite
	for _, csp := range sortedKeys(generated) {
		doc, err := k8s.ParseKubeconfig([]byte(generated[csp]))
		if err != nil {
			return nil, nil, fmt.Errorf("provider %s returned an unparsable kubeconfig: %w", csp, err)
		}
		doc.PrefixEntries(csp)
		rewrites = append(rewrites, doc.RewriteExecCommands(execPath)...)
		combined.Merge(doc)
	}

	return &mergedKubeconfig{doc: combined, contexts: combined.ContextNames()}, rewrites, nil
}

// writeMergedKubeconfig merges into the target kubeconfig and reports what changed.
func writeMergedKubeconfig(
	cmd *cobra.Command,
	flags kubeconfigFlags,
	merged *mergedKubeconfig,
	rewrites []k8s.ExecRewrite,
	failures []k8s.KubeconfigFailure,
) error {
	target := flags.file
	if target == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to resolve your home directory: %w", err)
		}
		target = k8s.ResolveKubeconfigPath(os.Getenv("KUBECONFIG"), home)
	}

	backedUp, err := k8s.BackupOnce(target)
	if err != nil {
		return err
	}

	existingData, err := os.ReadFile(target) //nolint:gosec // target is the user's chosen kubeconfig
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", target, err)
	}

	doc, err := k8s.ParseKubeconfig(existingData)
	if err != nil {
		return err
	}

	report := doc.Merge(merged.doc)
	if flags.setCurrentContext && len(merged.contexts) > 0 {
		doc.SetCurrentContext(merged.contexts[0])
	}

	data, err := doc.Bytes()
	if err != nil {
		return err
	}

	warnings, err := k8s.WriteKubeconfigAtomic(target, data)
	if err != nil {
		return err
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), kubeconfigOutput{
			Path:          target,
			Added:         report.Added,
			Replaced:      report.Replaced,
			Contexts:      merged.contexts,
			Warnings:      warnings,
			BackupCreated: backedUp,
			Failures:      failures,
		})
	}

	reportKubeconfigText(cmd, target, report, merged, rewrites, warnings, failures, backedUp)
	return nil
}

//nolint:gocritic // report and flags are grouped for readability, not hot-path performance
func reportKubeconfigText(
	cmd *cobra.Command,
	target string,
	report k8s.MergeReport,
	merged *mergedKubeconfig,
	rewrites []k8s.ExecRewrite,
	warnings []string,
	failures []k8s.KubeconfigFailure,
	backedUp bool,
) {
	errOut := cmd.ErrOrStderr()
	for _, w := range warnings {
		fmt.Fprintf(errOut, "Warning: %s\n", w)
	}
	for _, f := range failures {
		fmt.Fprintf(errOut, "Warning: %s kubeconfig generation failed: %s\n", f.CSP, f.Error)
	}
	for _, name := range report.Replaced {
		fmt.Fprintf(errOut, "Replaced existing entry %s\n", name)
	}
	for _, r := range rewrites {
		fmt.Fprintf(errOut, "Rewrote exec plugin for user %s: %s -> %s\n", r.User, r.From, r.To)
	}
	if backedUp {
		fmt.Fprintf(errOut, "Backed up your previous kubeconfig to %s.grant.bak\n", target)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Updated %s (%d added, %d replaced)\n", target, len(report.Added), len(report.Replaced))
	for _, name := range merged.contexts {
		fmt.Fprintf(out, "  kubectl --context %s get ns\n", name)
	}
}

func describeKubeconfigFailures(failures []k8s.KubeconfigFailure) string {
	if len(failures) == 0 {
		return "no eligible clusters were returned"
	}
	parts := make([]string, 0, len(failures))
	for _, f := range failures {
		parts = append(parts, f.CSP+": "+f.Error)
	}
	return strings.Join(parts, "; ")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
