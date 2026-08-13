package ui

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/k8s"
)

// FormatClusterOption formats an eligible cluster into a display string.
func FormatClusterOption(cluster k8s.Cluster) string {
	var b strings.Builder
	b.WriteString(cluster.Name)
	if cluster.Region != "" {
		fmt.Fprintf(&b, " (%s)", cluster.Region)
	}
	if cluster.Namespace != "" {
		fmt.Fprintf(&b, " [ns: %s]", cluster.Namespace)
	}
	if cluster.RoleName != "" {
		fmt.Fprintf(&b, " / Role: %s", cluster.RoleName)
	}
	if cluster.Provider != "" {
		fmt.Fprintf(&b, " (%s)", strings.ToLower(cluster.Provider))
	}
	return b.String()
}

// BuildClusterOptions builds a sorted list of display options from clusters.
func BuildClusterOptions(clusters []k8s.Cluster) []string {
	if len(clusters) == 0 {
		return []string{}
	}
	options := make([]string, len(clusters))
	for i, c := range clusters {
		options[i] = FormatClusterOption(c)
	}
	sort.Strings(options)
	return options
}

// FindClusterByDisplay finds a cluster by its formatted display string.
func FindClusterByDisplay(clusters []k8s.Cluster, display string) (*k8s.Cluster, error) {
	for i := range clusters {
		if FormatClusterOption(clusters[i]) == display {
			return &clusters[i], nil
		}
	}
	return nil, fmt.Errorf("cluster not found: %s", display)
}

// SelectCluster presents an interactive selector for choosing a cluster.
func SelectCluster(clusters []k8s.Cluster) (*k8s.Cluster, error) {
	if !IsInteractive() {
		return nil, fmt.Errorf("%w; pass a cluster name or --fqdn, or run 'grant k8s list' to see eligible clusters", ErrNotInteractive)
	}

	if len(clusters) == 0 {
		return nil, errors.New("no eligible clusters available")
	}

	options := BuildClusterOptions(clusters)

	var selected string
	prompt := &survey.Select{
		Message: "Select a cluster:",
		Options: options,
		Filter:  nil, // Enable default fuzzy filter
	}

	if err := survey.AskOne(prompt, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("cluster selection failed: %w", err)
	}

	return FindClusterByDisplay(clusters, selected)
}
