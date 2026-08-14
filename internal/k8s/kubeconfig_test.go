package k8s

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const existingKubeconfig = `apiVersion: v1
kind: Config
current-context: work
clusters:
  # my own cluster, do not touch
  - name: work
    cluster:
      server: https://work.example
      certificate-authority-data: d29yaw==
users:
  - name: work-user
    user:
      token: mytoken
contexts:
  - name: work
    context:
      cluster: work
      user: work-user
preferences: {}
`

const generatedKubeconfig = `apiVersion: v1
kind: Config
current-context: eks-prod
clusters:
  - name: eks-prod
    cluster:
      server: https://prod.eks.example
users:
  - name: eks-prod-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: idsec
        args:
          - sca
          - k8s
          - kubectl-login
          - --csp
          - aws
          - --fqdn
          - prod.eks.example
          - --role-id
          - arn:aws:iam::1:role/admin
contexts:
  - name: eks-prod
    context:
      cluster: eks-prod
      user: eks-prod-user
`

func decodeConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode kubeconfig: %v\n%s", err, data)
	}
	return out
}

func namesIn(t *testing.T, cfg map[string]any, section string) []string {
	t.Helper()
	list, _ := cfg[section].([]any)
	names := make([]string, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s entry is not a map: %#v", section, item)
		}
		name, _ := m["name"].(string)
		names = append(names, name)
	}
	return names
}

func entryByName(t *testing.T, cfg map[string]any, section, name string) map[string]any {
	t.Helper()
	list, _ := cfg[section].([]any)
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	t.Fatalf("%s entry %q not found", section, name)
	return nil
}

func TestMergePreservesExistingEntries(t *testing.T) {
	target, err := ParseKubeconfig([]byte(existingKubeconfig))
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	generated, err := ParseKubeconfig([]byte(generatedKubeconfig))
	if err != nil {
		t.Fatalf("parse generated: %v", err)
	}
	generated.PrefixEntries("aws")

	report := target.Merge(generated)
	out, err := target.Bytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	cfg := decodeConfig(t, out)

	// Every pre-existing entry survives untouched.
	original := decodeConfig(t, []byte(existingKubeconfig))
	for _, section := range []string{"clusters", "users", "contexts"} {
		for _, name := range namesIn(t, original, section) {
			got := entryByName(t, cfg, section, name)
			want := entryByName(t, original, section, name)
			if !yamlEqual(t, got, want) {
				t.Errorf("%s/%s changed:\ngot  %#v\nwant %#v", section, name, got, want)
			}
		}
	}

	// The YAML comment on the user's own cluster survives the round trip.
	if !strings.Contains(string(out), "my own cluster, do not touch") {
		t.Errorf("comment on an existing entry was lost:\n%s", out)
	}

	if len(report.Added) != 3 {
		t.Errorf("Added = %v, want 3 entries (cluster, user, context)", report.Added)
	}
	if len(report.Replaced) != 0 {
		t.Errorf("Replaced = %v, want none", report.Replaced)
	}
}

func TestMergePrefixesGrantOwnedNames(t *testing.T) {
	target, _ := ParseKubeconfig([]byte(existingKubeconfig))
	generated, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	generated.PrefixEntries("aws")

	target.Merge(generated)
	cfg := decodeConfig(t, mustBytes(t, target))

	if !containsString(namesIn(t, cfg, "clusters"), "grant-aws-eks-prod") {
		t.Errorf("clusters = %v, want a grant-aws- prefixed entry", namesIn(t, cfg, "clusters"))
	}

	ctx := entryByName(t, cfg, "contexts", "grant-aws-eks-prod")
	inner, _ := ctx["context"].(map[string]any)
	if inner["cluster"] != "grant-aws-eks-prod" || inner["user"] != "grant-aws-eks-prod-user" {
		t.Errorf("context references were not remapped: %#v", inner)
	}
}

func TestMergeReplacesCollidingGrantEntry(t *testing.T) {
	target, _ := ParseKubeconfig([]byte(existingKubeconfig))
	generated, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	generated.PrefixEntries("aws")
	target.Merge(generated)

	// Merge the same generated config again: entries are replaced, not duplicated.
	second, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	second.PrefixEntries("aws")
	report := target.Merge(second)

	cfg := decodeConfig(t, mustBytes(t, target))
	count := 0
	for _, n := range namesIn(t, cfg, "clusters") {
		if n == "grant-aws-eks-prod" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("grant-aws-eks-prod appears %d times, want 1", count)
	}
	if len(report.Replaced) != 3 {
		t.Errorf("Replaced = %v, want 3", report.Replaced)
	}
	if len(report.Added) != 0 {
		t.Errorf("Added = %v, want none", report.Added)
	}
}

func TestMergeLeavesCurrentContextAlone(t *testing.T) {
	target, _ := ParseKubeconfig([]byte(existingKubeconfig))
	generated, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	generated.PrefixEntries("aws")
	target.Merge(generated)

	if got := target.CurrentContext(); got != "work" {
		t.Errorf("current-context = %q, want it unchanged (work)", got)
	}

	target.SetCurrentContext("grant-aws-eks-prod")
	if got := target.CurrentContext(); got != "grant-aws-eks-prod" {
		t.Errorf("current-context = %q after explicit opt-in", got)
	}
}

func TestMergeIntoEmptyKubeconfig(t *testing.T) {
	target, err := ParseKubeconfig(nil)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	generated, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	generated.PrefixEntries("aws")
	target.Merge(generated)

	cfg := decodeConfig(t, mustBytes(t, target))
	if cfg["apiVersion"] != "v1" || cfg["kind"] != "Config" {
		t.Errorf("empty target did not get a valid kubeconfig skeleton: %#v", cfg)
	}
	if len(namesIn(t, cfg, "clusters")) != 1 {
		t.Errorf("clusters = %v, want 1", namesIn(t, cfg, "clusters"))
	}
	// An empty target has no current-context; adopting the single new one is fine
	// only when explicitly asked for.
	if cfg["current-context"] != nil && cfg["current-context"] != "" {
		t.Errorf("current-context = %v, want empty by default", cfg["current-context"])
	}
}

// R-5a: the DPA-generated kubeconfig points exec.command at the official CLI.
func TestRewriteExecCommands(t *testing.T) {
	generated, _ := ParseKubeconfig([]byte(generatedKubeconfig))
	rewrites := generated.RewriteExecCommands("/usr/local/bin/grant")

	if len(rewrites) != 1 {
		t.Fatalf("got %d rewrites, want 1: %+v", len(rewrites), rewrites)
	}
	if rewrites[0].From != "idsec" {
		t.Errorf("From = %q, want idsec", rewrites[0].From)
	}

	cfg := decodeConfig(t, mustBytes(t, generated))
	user := entryByName(t, cfg, "users", "eks-prod-user")
	exec, _ := user["user"].(map[string]any)["exec"].(map[string]any)
	if exec["command"] != "/usr/local/bin/grant" {
		t.Errorf("command = %v, want the grant binary path", exec["command"])
	}

	args, _ := exec["args"].([]any)
	got := make([]string, len(args))
	for i, a := range args {
		got[i], _ = a.(string)
	}
	want := []string{
		"k8s", "exec-credential",
		"--csp", "aws",
		"--fqdn", "prod.eks.example",
		"--role-id", "arn:aws:iam::1:role/admin",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", got, want)
	}
}

func TestRewriteExecCommandsLeavesForeignPluginsAlone(t *testing.T) {
	const foreign = `apiVersion: v1
kind: Config
users:
  - name: gke
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: gke-gcloud-auth-plugin
`
	cfg, _ := ParseKubeconfig([]byte(foreign))
	if rewrites := cfg.RewriteExecCommands("/usr/local/bin/grant"); len(rewrites) != 0 {
		t.Fatalf("rewrote a foreign exec plugin: %+v", rewrites)
	}

	out := decodeConfig(t, mustBytes(t, cfg))
	user := entryByName(t, out, "users", "gke")
	exec, _ := user["user"].(map[string]any)["exec"].(map[string]any)
	if exec["command"] != "gke-gcloud-auth-plugin" {
		t.Errorf("foreign command was modified: %v", exec["command"])
	}
}

// ResolveKubeconfigPath must follow kubectl's write rule: the first entry that
// EXISTS, or the last entry when none do. Always taking the first entry would
// create a new file that shadows the user's real config.
func TestResolveKubeconfigPath(t *testing.T) {
	sep := string(os.PathListSeparator)
	testHome := filepath.Join(string(filepath.Separator)+"home", "u")
	homeKubeconfig := filepath.Join(testHome, ".kube", "config")

	dir := t.TempDir()
	existingA := filepath.Join(dir, "a")
	existingB := filepath.Join(dir, "b")
	missing1 := filepath.Join(dir, "missing1")
	missing2 := filepath.Join(dir, "missing2")
	for _, p := range []string{existingA, existingB} {
		if err := os.WriteFile(p, []byte("apiVersion: v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "unset falls back to home", env: "", want: homeKubeconfig},
		{name: "single existing path", env: existingA, want: existingA},
		{name: "single missing path is still the target", env: missing1, want: missing1},
		{name: "first existing entry wins", env: existingA + sep + existingB, want: existingA},
		{
			name: "skips a missing earlier entry rather than creating it",
			env:  missing1 + sep + existingB,
			want: existingB,
		},
		{name: "none exist falls back to the last entry", env: missing1 + sep + missing2, want: missing2},
		{name: "leading empty entry is skipped", env: sep + existingB, want: existingB},
		{name: "all empty falls back to home", env: sep + sep, want: homeKubeconfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveKubeconfigPath(tt.env, testHome); got != tt.want {
				t.Errorf("ResolveKubeconfigPath(%q) = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

// client-go REQUIRES interactiveMode for client.authentication.k8s.io/v1 and
// rejects the kubeconfig before grant is ever invoked when it is missing.
func TestRewriteExecCommandsSetsInteractiveMode(t *testing.T) {
	const v1Generated = `apiVersion: v1
kind: Config
users:
  - name: eks-prod-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: idsec
        args: ["sca", "k8s", "kubectl-login", "--csp", "aws", "--fqdn", "prod.eks.example"]
`
	cfg, err := ParseKubeconfig([]byte(v1Generated))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rewrites := cfg.RewriteExecCommands("/usr/local/bin/grant"); len(rewrites) != 1 {
		t.Fatalf("got %d rewrites, want 1", len(rewrites))
	}

	out := decodeConfig(t, mustBytes(t, cfg))
	user := entryByName(t, out, "users", "eks-prod-user")
	exec, _ := user["user"].(map[string]any)["exec"].(map[string]any)
	if exec["interactiveMode"] != "IfAvailable" {
		t.Errorf("interactiveMode = %v, want IfAvailable (required for the v1 API)", exec["interactiveMode"])
	}
}

func TestRewriteExecCommandsPreservesExplicitInteractiveMode(t *testing.T) {
	const withMode = `apiVersion: v1
kind: Config
users:
  - name: u
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: idsec
        interactiveMode: Never
`
	cfg, _ := ParseKubeconfig([]byte(withMode))
	cfg.RewriteExecCommands("/usr/local/bin/grant")

	out := decodeConfig(t, mustBytes(t, cfg))
	exec, _ := entryByName(t, out, "users", "u")["user"].(map[string]any)["exec"].(map[string]any)
	if exec["interactiveMode"] != "Never" {
		t.Errorf("interactiveMode = %v, want the explicit value preserved", exec["interactiveMode"])
	}
}

// Two concurrent runs must not clobber each other's backup.
func TestBackupOnceIsExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(existingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	const runs = 8
	results := make(chan bool, runs)
	errs := make(chan error, runs)
	start := make(chan struct{})

	for range runs {
		go func() {
			<-start
			created, err := BackupOnce(path)
			results <- created
			errs <- err
		}()
	}
	close(start)

	created := 0
	for range runs {
		if <-results {
			created++
		}
		if err := <-errs; err != nil {
			t.Errorf("BackupOnce: %v", err)
		}
	}

	if created != 1 {
		t.Errorf("%d goroutines reported creating the backup, want exactly 1", created)
	}
	data, err := os.ReadFile(path + ".grant.bak") //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(data) != existingKubeconfig {
		t.Error("the backup content was corrupted by concurrent writers")
	}
}

// TestBackupOnceRefusesNonRegularSource runs on every platform, Windows
// included. BackupOnce documents that it refuses a symlinked kubeconfig rather
// than dereferencing it; that promise was false on Windows while this test
// skipped there.
func TestBackupOnceRefusesNonRegularSource(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(realPath, []byte(existingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, realPath, link)

	if _, err := BackupOnce(link); err == nil {
		t.Fatal("expected a symlinked kubeconfig to be refused")
	}
	// The backup must not have been created from the dereferenced target.
	if _, err := os.Lstat(link + ".grant.bak"); !os.IsNotExist(err) {
		t.Error("a symlinked kubeconfig was backed up anyway")
	}
}

// TestBackupOnceLeavesNoPartialBackup covers the integrity gap: a backup that
// exists is treated as complete by every later run (BackupOnce returns early on
// os.IsExist, and the kubeconfig command then replaces the real file believing
// a good copy is on disk). A write that fails halfway must therefore leave
// nothing behind rather than a truncated file wearing the backup's name.
func TestBackupOnceLeavesNoPartialBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(existingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	original := backupWrite
	t.Cleanup(func() { backupWrite = original })
	backupWrite = func(f *os.File, data []byte) error {
		// A short write, as a full disk or a killed NFS mount would produce.
		_, _ = f.Write(data[:len(data)/2])
		_ = f.Close()
		return errors.New("no space left on device")
	}

	if _, err := BackupOnce(path); err == nil {
		t.Fatal("expected the failed backup write to be reported")
	}
	if _, err := os.Lstat(path + ".grant.bak"); !os.IsNotExist(err) {
		t.Fatal("a partial backup was left on disk; the next run would mistake it for a complete one")
	}

	// And the next attempt, with a working writer, produces a complete backup.
	backupWrite = original
	created, err := BackupOnce(path)
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if !created {
		t.Fatal("expected the retry to create the backup")
	}
	data, err := os.ReadFile(path + ".grant.bak")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existingKubeconfig {
		t.Errorf("backup content = %q, want the full kubeconfig", string(data))
	}
}

func TestWriteAtomicCreatesFileWithSecureModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}

	dir := filepath.Join(t.TempDir(), "nested", "kube")
	path := filepath.Join(dir, "config")

	if _, err := WriteKubeconfigAtomic(path, []byte("apiVersion: v1\n")); err != nil {
		t.Fatalf("WriteKubeconfigAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 0600", fi.Mode().Perm())
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 0700", di.Mode().Perm())
	}
}

func TestWriteAtomicDoesNotWidenExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("old"), 0o400); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteKubeconfigAtomic(path, []byte("new")); err != nil {
		t.Fatalf("WriteKubeconfigAtomic: %v", err)
	}

	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("mode = %o, want the existing narrower 0400 preserved", fi.Mode().Perm())
	}
}

func TestWriteAtomicWarnsOnWorldReadableTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	warnings, err := WriteKubeconfigAtomic(path, []byte("new"))
	if err != nil {
		t.Fatalf("WriteKubeconfigAtomic: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning about the world-readable target")
	}
	if !strings.Contains(warnings[0], "644") {
		t.Errorf("warning should mention the offending mode: %q", warnings[0])
	}

	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want the file re-secured to 0600", fi.Mode().Perm())
	}
}

func TestWriteAtomicUsesTempFileInSameDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	var tmpDir string
	original := kubeconfigWriteFailPoint
	t.Cleanup(func() { kubeconfigWriteFailPoint = original })
	kubeconfigWriteFailPoint = func(tmp string) error {
		tmpDir = filepath.Dir(tmp)
		return nil
	}

	if _, err := WriteKubeconfigAtomic(path, []byte("data")); err != nil {
		t.Fatalf("WriteKubeconfigAtomic: %v", err)
	}
	if tmpDir != dir {
		t.Errorf("temp file created in %q, want the target directory %q", tmpDir, dir)
	}
}

func TestWriteAtomicLeavesOriginalIntactOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(existingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("interrupted")
	original := kubeconfigWriteFailPoint
	t.Cleanup(func() { kubeconfigWriteFailPoint = original })
	kubeconfigWriteFailPoint = func(string) error { return boom }

	if _, err := WriteKubeconfigAtomic(path, []byte("clobbered")); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	got, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("original file is gone: %v", err)
	}
	if string(got) != existingKubeconfig {
		t.Errorf("original file was modified:\n%s", got)
	}

	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory has %d entries, want only the original file", len(entries))
	}
}

func TestBackupOnceCreatesSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(existingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	created, err := BackupOnce(path)
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if !created {
		t.Error("expected a backup to be created")
	}

	data, err := os.ReadFile(path + ".grant.bak") //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(data) != existingKubeconfig {
		t.Error("backup content differs from the original")
	}

	// A second call must not overwrite the first backup.
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err = BackupOnce(path)
	if err != nil {
		t.Fatalf("BackupOnce (second): %v", err)
	}
	if created {
		t.Error("backup was recreated; it must only be written once")
	}
	data, _ = os.ReadFile(path + ".grant.bak") //nolint:gosec // test-controlled path
	if string(data) != existingKubeconfig {
		t.Error("existing backup was overwritten")
	}
}

func TestBackupOnceNoopWhenTargetMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	created, err := BackupOnce(path)
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if created {
		t.Error("expected no backup for a non-existent target")
	}
}

func mustBytes(t *testing.T, k *Kubeconfig) []byte {
	t.Helper()
	data, err := k.Bytes()
	if err != nil {
		t.Fatalf("serialize kubeconfig: %v", err)
	}
	return data
}

func yamlEqual(t *testing.T, a, b any) bool {
	t.Helper()
	ay, err := yaml.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	by, err := yaml.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ay, by)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
