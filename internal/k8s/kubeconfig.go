package k8s

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubeconfigSections are the named-entry lists grant merges into.
var kubeconfigSections = []string{"clusters", "users", "contexts"}

// execPluginBinaries are the official CLI binaries whose exec stanzas grant
// rewrites to point at itself (risk R-5a). Anything else is left alone.
var execPluginBinaries = map[string]bool{
	"idsec":     true,
	"idsec-cli": true,
	"ark":       true,
	"ark-cli":   true,
}

// execPassThroughFlags are the kubectl-login flags grant's exec-credential
// command understands and therefore preserves when rewriting an exec stanza.
var execPassThroughFlags = map[string]bool{
	"--csp":             true,
	"--fqdn":            true,
	"--role-id":         true,
	"--organization-id": true,
	"--namespace":       true,
}

// kubeconfigWriteFailPoint is an injectable hook fired after the temp file is
// fully written and before the rename. Tests use it to simulate an interrupted
// write; it is nil in production.
var kubeconfigWriteFailPoint func(tmpPath string) error

// Kubeconfig is a parsed kubeconfig document. It keeps the original YAML node
// tree so entries grant does not own survive re-serialization with their
// structure and comments intact.
type Kubeconfig struct {
	root *yaml.Node
}

// MergeReport records what a merge did, for reporting on stderr.
type MergeReport struct {
	Added    []string
	Replaced []string
}

// ExecRewrite records a rewritten exec-credential stanza.
type ExecRewrite struct {
	User string
	From string
	To   string
}

// ParseKubeconfig parses kubeconfig YAML. Empty input yields a valid skeleton.
func ParseKubeconfig(data []byte) (*Kubeconfig, error) {
	if strings.TrimSpace(string(data)) == "" {
		return &Kubeconfig{root: newKubeconfigSkeleton()}, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, errors.New("kubeconfig is not a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("kubeconfig root is not a YAML mapping")
	}
	return &Kubeconfig{root: root}, nil
}

// Bytes serializes the kubeconfig back to YAML.
func (k *Kubeconfig) Bytes() ([]byte, error) {
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(k.root); err != nil {
		return nil, fmt.Errorf("failed to serialize kubeconfig: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("failed to serialize kubeconfig: %w", err)
	}
	return []byte(sb.String()), nil
}

// CurrentContext returns the current-context value, or "" when unset.
func (k *Kubeconfig) CurrentContext() string {
	if node := mapGet(k.root, "current-context"); node != nil {
		return node.Value
	}
	return ""
}

// SetCurrentContext sets current-context. Callers must only do this behind an
// explicit user opt-in: silently repointing kubectl is a production foot-gun.
func (k *Kubeconfig) SetCurrentContext(name string) {
	mapSet(k.root, "current-context", scalarNode(name))
}

// ContextNames returns every context name in the document.
func (k *Kubeconfig) ContextNames() []string {
	seq := mapGet(k.root, "contexts")
	if seq == nil {
		return nil
	}
	names := make([]string, 0, len(seq.Content))
	for _, entry := range seq.Content {
		if name := mapGet(entry, "name"); name != nil {
			names = append(names, name.Value)
		}
	}
	return names
}

// PrefixEntries renames every cluster, user and context to a deterministic
// grant-owned name (grant-<csp>-<original>) and remaps context references, so
// ownership is decidable on the next merge without extra state.
func (k *Kubeconfig) PrefixEntries(csp string) {
	prefix := "grant-" + strings.ToLower(strings.TrimSpace(csp)) + "-"

	renames := map[string]map[string]string{}
	for _, section := range kubeconfigSections {
		renames[section] = renameSection(mapGet(k.root, section), prefix)
	}

	// Remap each context's cluster/user references through the rename maps.
	contexts := mapGet(k.root, "contexts")
	if contexts == nil {
		return
	}
	for _, entry := range contexts.Content {
		inner := mapGet(entry, "context")
		if inner == nil {
			continue
		}
		remapRef(inner, "cluster", renames["clusters"])
		remapRef(inner, "user", renames["users"])
	}
}

func renameSection(seq *yaml.Node, prefix string) map[string]string {
	renames := map[string]string{}
	if seq == nil {
		return renames
	}
	for _, entry := range seq.Content {
		name := mapGet(entry, "name")
		if name == nil || name.Value == "" || strings.HasPrefix(name.Value, prefix) {
			continue
		}
		renamed := prefix + name.Value
		renames[name.Value] = renamed
		name.Value = renamed
	}
	return renames
}

func remapRef(inner *yaml.Node, key string, renames map[string]string) {
	ref := mapGet(inner, key)
	if ref == nil {
		return
	}
	if renamed, ok := renames[ref.Value]; ok {
		ref.Value = renamed
	}
}

// Merge folds other's clusters, users and contexts into k. Entries whose names
// collide are replaced; everything else in k is left untouched, including
// current-context.
func (k *Kubeconfig) Merge(other *Kubeconfig) MergeReport {
	ensureScalar(k.root, "apiVersion", "v1")
	ensureScalar(k.root, "kind", "Config")

	var report MergeReport
	for _, section := range kubeconfigSections {
		incoming := mapGet(other.root, section)
		if incoming == nil {
			continue
		}
		target := ensureSequence(k.root, section)
		for _, entry := range incoming.Content {
			name := mapGet(entry, "name")
			if name == nil {
				continue
			}
			if idx := indexByName(target, name.Value); idx >= 0 {
				target.Content[idx] = entry
				report.Replaced = append(report.Replaced, section+"/"+name.Value)
				continue
			}
			target.Content = append(target.Content, entry)
			report.Added = append(report.Added, section+"/"+name.Value)
		}
	}
	return report
}

// RewriteExecCommands repoints exec-credential plugin stanzas at grantPath.
//
// R-5a: the DPA-generated kubeconfig is expected to reference the official
// idsec/ark CLI. This rewrite is deliberately conservative — a stanza is only
// touched when its command basename is a known official binary, and only flags
// grant's own exec-credential command understands are carried over. Everything
// else passes through untouched. This has not been validated against a live
// tenant's generated kubeconfig.
func (k *Kubeconfig) RewriteExecCommands(grantPath string) []ExecRewrite {
	users := mapGet(k.root, "users")
	if users == nil {
		return nil
	}

	var rewrites []ExecRewrite
	for _, entry := range users.Content {
		userName := ""
		if n := mapGet(entry, "name"); n != nil {
			userName = n.Value
		}
		exec := execNode(entry)
		if exec == nil {
			continue
		}
		command := mapGet(exec, "command")
		if command == nil || !isOfficialCLIBinary(command.Value) {
			continue
		}

		rewrites = append(rewrites, ExecRewrite{User: userName, From: command.Value, To: grantPath})
		command.Value = grantPath
		mapSet(exec, "args", sequenceNode(rewriteExecArgs(mapGet(exec, "args"))))
		ensureInteractiveMode(exec)
	}
	return rewrites
}

// ensureInteractiveMode guarantees the exec stanza carries an interactiveMode.
//
// client-go REQUIRES interactiveMode for client.authentication.k8s.io/v1 (it is
// only optional in v1beta1), and rejects the kubeconfig outright when it is
// missing — before grant is ever invoked. "IfAvailable" is the right value for
// grant: it replays cached credentials without stdin, and can run a browser or
// `az login` flow when kubectl says stdin is available.
func ensureInteractiveMode(exec *yaml.Node) {
	if node := mapGet(exec, "interactiveMode"); node != nil && strings.TrimSpace(node.Value) != "" {
		return
	}
	mapSet(exec, "interactiveMode", scalarNode("IfAvailable"))
}

func execNode(userEntry *yaml.Node) *yaml.Node {
	inner := mapGet(userEntry, "user")
	if inner == nil {
		return nil
	}
	exec := mapGet(inner, "exec")
	if exec == nil || exec.Kind != yaml.MappingNode {
		return nil
	}
	return exec
}

func isOfficialCLIBinary(command string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	base = strings.TrimSuffix(base, ".exe")
	return execPluginBinaries[base]
}

// rewriteExecArgs rebuilds the argument vector for grant's exec-credential
// command, carrying over only recognized flags.
func rewriteExecArgs(args *yaml.Node) []string {
	out := []string{"k8s", "exec-credential"}
	if args == nil || args.Kind != yaml.SequenceNode {
		return out
	}

	for i := 0; i < len(args.Content); i++ {
		arg := args.Content[i].Value
		flag, inlineValue, hasInline := strings.Cut(arg, "=")
		if !execPassThroughFlags[flag] {
			continue
		}
		if hasInline {
			out = append(out, flag, inlineValue)
			continue
		}
		if i+1 < len(args.Content) {
			out = append(out, flag, args.Content[i+1].Value)
			i++
		}
	}
	return out
}

// ResolveKubeconfigPath returns the kubeconfig grant writes to, following
// kubectl's own write rule for a $KUBECONFIG list: the first file in the list
// that EXISTS, or — when none of them exist — the last entry. Writing to the
// first entry unconditionally would create a brand-new file that shadows the
// user's real config instead of updating it.
//
// Note that kubectl READS the whole chain and merges it with the first file
// winning on a name collision, so writing to the first existing file is also the
// only placement that guarantees grant's entries are the ones kubectl resolves.
// grant merges into exactly one file and never rewrites the rest of the chain.
func ResolveKubeconfigPath(kubeconfigEnv, home string) string {
	var entries []string
	for _, entry := range filepath.SplitList(kubeconfigEnv) {
		if strings.TrimSpace(entry) != "" {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return filepath.Join(home, ".kube", "config")
	}

	for _, entry := range entries {
		if _, err := os.Stat(entry); err == nil {
			return entry
		}
	}
	return entries[len(entries)-1]
}

// WriteKubeconfigAtomic writes data to path via a temp file in the same
// directory followed by a rename, so an interrupted write can never leave a
// truncated kubeconfig behind. It returns any permission warnings.
func WriteKubeconfigAtomic(path string, data []byte) ([]string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", dir, err)
	}

	perm, warnings := targetFileMode(path)

	tmp, err := os.CreateTemp(dir, ".grant-kubeconfig-*.tmp")
	if err != nil {
		return warnings, fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	if err := writeTempFile(tmp, data, perm); err != nil {
		_ = os.Remove(tmpName)
		return warnings, err
	}

	if kubeconfigWriteFailPoint != nil {
		if err := kubeconfigWriteFailPoint(tmpName); err != nil {
			_ = os.Remove(tmpName)
			return warnings, err
		}
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return warnings, fmt.Errorf("failed to replace %s: %w", path, err)
	}
	return warnings, nil
}

func writeTempFile(tmp *os.File, data []byte, perm os.FileMode) error {
	defer func() { _ = tmp.Close() }()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to flush kubeconfig: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set kubeconfig permissions: %w", err)
	}
	return nil
}

// targetFileMode decides the mode for the written file: 0600 by default, an
// existing narrower mode is preserved, and an existing group/world-accessible
// mode is tightened with a warning.
func targetFileMode(path string) (perm os.FileMode, warnings []string) {
	// Windows synthesizes permission bits from a read-only attribute (every
	// ordinary file reads as 0666), so a POSIX 0077 check there would warn on
	// every run and mean nothing.
	if !posixPermissions {
		return 0o600, nil
	}

	fi, err := os.Stat(path)
	if err != nil {
		return 0o600, nil
	}
	mode := fi.Mode().Perm()
	if mode&0o077 != 0 {
		return 0o600, []string{fmt.Sprintf(
			"%s is mode %o and readable beyond your user; grant is rewriting it as 0600", path, mode)}
	}
	if mode&^os.FileMode(0o600) == 0 && mode != 0 {
		return mode, nil
	}
	return 0o600, nil
}

// BackupOnce writes <path>.grant.bak the first time grant merges into an
// existing kubeconfig. It never overwrites an existing backup.
//
// The backup is created with O_EXCL so two concurrent grant runs cannot clobber
// each other's copy, and the source must be a regular file — a symlinked or
// special kubeconfig is refused rather than dereferenced into a new file.
func BackupOnce(path string) (bool, error) {
	// Open first, then validate through the descriptor, so the file that is
	// checked is the file that is read. A path-based Lstat followed by a read
	// would let the path be swapped in between, and unlike the credential cache
	// this directory has no privacy guarantee to lean on.
	src, err := openNoFollowRead(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		if isSymlinkOpenError(err) {
			return false, fmt.Errorf("refusing to back up %s: it is a symlink, and grant will not dereference one", path)
		}
		return false, fmt.Errorf("failed to open %s for backup: %w", path, err)
	}
	defer func() { _ = src.Close() }()

	fi, err := src.Stat()
	if err != nil {
		return false, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("refusing to back up %s: not a regular file", path)
	}

	data, err := io.ReadAll(src)
	if err != nil {
		return false, fmt.Errorf("failed to read %s for backup: %w", path, err)
	}

	backup := path + ".grant.bak"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to write %s: %w", backup, err)
	}

	// A backup that exists is treated as complete by the next run (the O_EXCL
	// above returns early on os.IsExist), and cmd/k8s_kubeconfig.go will then
	// happily replace the kubeconfig believing a good copy is on disk. So a
	// backup that was not written in full must not be left behind: remove it and
	// report, rather than leaving a truncated file wearing the name of a backup.
	if err := backupWrite(f, data); err != nil {
		_ = os.Remove(backup)
		return false, fmt.Errorf("failed to write %s: %w", backup, err)
	}
	return true, nil
}

// backupWrite writes and durably closes the backup file. It is a package var so
// tests can inject a mid-write failure, which is otherwise unreachable.
var backupWrite = func(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// --- yaml.Node helpers ---

func mapGet(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func mapSet(node *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1] = value
			return
		}
	}
	node.Content = append(node.Content, scalarNode(key), value)
}

func ensureScalar(node *yaml.Node, key, value string) {
	if mapGet(node, key) == nil {
		mapSet(node, key, scalarNode(value))
	}
}

func ensureSequence(node *yaml.Node, key string) *yaml.Node {
	existing := mapGet(node, key)
	if existing != nil && existing.Kind == yaml.SequenceNode {
		return existing
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	mapSet(node, key, seq)
	return seq
}

func indexByName(seq *yaml.Node, name string) int {
	for i, entry := range seq.Content {
		if n := mapGet(entry, "name"); n != nil && n.Value == name {
			return i
		}
	}
	return -1
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func sequenceNode(values []string) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		seq.Content = append(seq.Content, scalarNode(v))
	}
	return seq
}

func newKubeconfigSkeleton() *yaml.Node {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapSet(root, "apiVersion", scalarNode("v1"))
	mapSet(root, "kind", scalarNode("Config"))
	for _, section := range kubeconfigSections {
		mapSet(root, section, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
	}
	return root
}
