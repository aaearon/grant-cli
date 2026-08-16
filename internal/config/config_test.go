package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "config.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}

	def := DefaultConfig()
	if cfg.Profile != def.Profile {
		t.Errorf("profile = %q, want %q", cfg.Profile, def.Profile)
	}
	if cfg.DefaultProvider != def.DefaultProvider {
		t.Errorf("default_provider = %q, want %q", cfg.DefaultProvider, def.DefaultProvider)
	}
	if len(cfg.Favorites) != 0 {
		t.Errorf("favorites length = %d, want 0", len(cfg.Favorites))
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte(`profile: my-profile
default_provider: aws
favorites:
  prod-admin:
    provider: azure
    target: sub-123
    role: Owner
  dev-reader:
    provider: aws
    target: account-456
    role: ReadOnly
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Profile != "my-profile" {
		t.Errorf("profile = %q, want %q", cfg.Profile, "my-profile")
	}
	if cfg.DefaultProvider != "aws" {
		t.Errorf("default_provider = %q, want %q", cfg.DefaultProvider, "aws")
	}
	if len(cfg.Favorites) != 2 {
		t.Fatalf("favorites length = %d, want 2", len(cfg.Favorites))
	}

	prod, ok := cfg.Favorites["prod-admin"]
	if !ok {
		t.Fatal("expected favorite 'prod-admin' to exist")
	}
	if prod.Provider != "azure" {
		t.Errorf("prod-admin provider = %q, want %q", prod.Provider, "azure")
	}
	if prod.Target != "sub-123" {
		t.Errorf("prod-admin target = %q, want %q", prod.Target, "sub-123")
	}
	if prod.Role != "Owner" {
		t.Errorf("prod-admin role = %q, want %q", prod.Role, "Owner")
	}

	dev, ok := cfg.Favorites["dev-reader"]
	if !ok {
		t.Fatal("expected favorite 'dev-reader' to exist")
	}
	if dev.Provider != "aws" {
		t.Errorf("dev-reader provider = %q, want %q", dev.Provider, "aws")
	}
	if dev.Target != "account-456" {
		t.Errorf("dev-reader target = %q, want %q", dev.Target, "account-456")
	}
	if dev.Role != "ReadOnly" {
		t.Errorf("dev-reader role = %q, want %q", dev.Role, "ReadOnly")
	}
}

func TestSaveConfig_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "config.yaml")

	cfg := DefaultConfig()
	if err := Save(cfg, path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected config file to be created")
	}
}

func TestSaveConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := &Config{
		Profile:         "test-profile",
		DefaultProvider: "aws",
		Favorites: map[string]Favorite{
			"my-fav": {
				Provider: "azure",
				Target:   "sub-999",
				Role:     "Contributor",
			},
		},
	}

	if err := Save(original, path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Profile != original.Profile {
		t.Errorf("profile = %q, want %q", loaded.Profile, original.Profile)
	}
	if loaded.DefaultProvider != original.DefaultProvider {
		t.Errorf("default_provider = %q, want %q", loaded.DefaultProvider, original.DefaultProvider)
	}
	if len(loaded.Favorites) != len(original.Favorites) {
		t.Fatalf("favorites length = %d, want %d", len(loaded.Favorites), len(original.Favorites))
	}

	fav, ok := loaded.Favorites["my-fav"]
	if !ok {
		t.Fatal("expected favorite 'my-fav' to exist")
	}
	origFav := original.Favorites["my-fav"]
	if fav.Provider != origFav.Provider {
		t.Errorf("provider = %q, want %q", fav.Provider, origFav.Provider)
	}
	if fav.Target != origFav.Target {
		t.Errorf("target = %q, want %q", fav.Target, origFav.Target)
	}
	if fav.Role != origFav.Role {
		t.Errorf("role = %q, want %q", fav.Role, origFav.Role)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Profile != "grant" {
		t.Errorf("profile = %q, want %q", cfg.Profile, "grant")
	}
	if cfg.DefaultProvider != "azure" {
		t.Errorf("default_provider = %q, want %q", cfg.DefaultProvider, "azure")
	}
	if cfg.Favorites == nil {
		t.Fatal("favorites should not be nil")
	}
	if len(cfg.Favorites) != 0 {
		t.Errorf("favorites length = %d, want 0", len(cfg.Favorites))
	}
}

func TestLoadConfig_PermissionError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0000 does not make a file unreadable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Create a file, then make it unreadable
	if err := os.WriteFile(path, []byte("profile: test"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unreadable file, got nil")
	}
}

func TestConfigPath_Override(t *testing.T) {
	customPath := "/tmp/custom-grant/config.yaml"

	t.Setenv("GRANT_CONFIG", customPath)

	got, err := ConfigPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != customPath {
		t.Errorf("ConfigPath() = %q, want %q", got, customPath)
	}
}

func TestConfigDir_Error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserHomeDir uses USERPROFILE on Windows, not HOME")
	}
	// Override HOME to empty to force error
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	_, err := ConfigDir()
	if err == nil {
		t.Error("expected error when HOME is not set")
	}
}

func TestLoadDefaultWithPath_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := DefaultConfig()
	_ = Save(cfg, configPath)

	loaded, path, err := LoadDefaultWithPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != configPath {
		t.Errorf("path = %q, want %q", path, configPath)
	}
	if loaded.Profile != "grant" {
		t.Errorf("profile = %q, want %q", loaded.Profile, "grant")
	}
}

func TestLoadDefaultWithPath_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent", "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg, path, err := LoadDefaultWithPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != configPath {
		t.Errorf("path = %q, want %q", path, configPath)
	}
	if cfg.Profile != "grant" {
		t.Errorf("expected default config, got profile = %q", cfg.Profile)
	}
}

func TestConfigPath_Default(t *testing.T) {
	t.Setenv("GRANT_CONFIG", "")

	got, err := ConfigPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Error("expected non-empty config path")
	}
}

func TestSaveConfig_RoundTrip_GroupFavorite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := &Config{
		Profile:         "test-profile",
		DefaultProvider: "azure",
		Favorites: map[string]Favorite{
			"my-group": {
				Type:        FavoriteTypeGroups,
				Provider:    "azure",
				Group:       "SG-Admin",
				DirectoryID: "dir-abc-123",
			},
		},
	}

	if err := Save(original, path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	fav, ok := loaded.Favorites["my-group"]
	if !ok {
		t.Fatal("expected favorite 'my-group' to exist")
	}
	if fav.Type != FavoriteTypeGroups {
		t.Errorf("type = %q, want %q", fav.Type, FavoriteTypeGroups)
	}
	if fav.Provider != "azure" {
		t.Errorf("provider = %q, want %q", fav.Provider, "azure")
	}
	if fav.Group != "SG-Admin" {
		t.Errorf("group = %q, want %q", fav.Group, "SG-Admin")
	}
	if fav.DirectoryID != "dir-abc-123" {
		t.Errorf("directory_id = %q, want %q", fav.DirectoryID, "dir-abc-123")
	}
}

func TestLoadConfig_LegacyWithoutType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Legacy YAML: no type field
	content := []byte(`profile: legacy-profile
default_provider: azure
favorites:
  old-fav:
    provider: azure
    target: sub-999
    role: Reader
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	fav, ok := cfg.Favorites["old-fav"]
	if !ok {
		t.Fatal("expected favorite 'old-fav' to exist")
	}
	if fav.Type != "" {
		t.Errorf("type = %q, want empty string for legacy favorite", fav.Type)
	}
	if fav.ResolvedType() != FavoriteTypeCloud {
		t.Errorf("ResolvedType() = %q, want %q", fav.ResolvedType(), FavoriteTypeCloud)
	}
	if fav.Provider != "azure" {
		t.Errorf("provider = %q, want %q", fav.Provider, "azure")
	}
	if fav.Target != "sub-999" {
		t.Errorf("target = %q, want %q", fav.Target, "sub-999")
	}
	if fav.Role != "Reader" {
		t.Errorf("role = %q, want %q", fav.Role, "Reader")
	}
}

func TestLoadConfig_MixedFavorites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte(`profile: mixed-profile
default_provider: azure
favorites:
  cloud-fav:
    type: cloud
    provider: aws
    target: account-123
    role: Admin
  group-fav:
    type: groups
    provider: azure
    group: SG-Dev
    directory_id: dir-xyz
  legacy-fav:
    provider: azure
    target: sub-old
    role: Reader
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Favorites) != 3 {
		t.Fatalf("favorites length = %d, want 3", len(cfg.Favorites))
	}

	cloud := cfg.Favorites["cloud-fav"]
	if cloud.Type != FavoriteTypeCloud {
		t.Errorf("cloud-fav type = %q, want %q", cloud.Type, FavoriteTypeCloud)
	}
	if cloud.Provider != "aws" {
		t.Errorf("cloud-fav provider = %q, want %q", cloud.Provider, "aws")
	}
	if cloud.Target != "account-123" {
		t.Errorf("cloud-fav target = %q, want %q", cloud.Target, "account-123")
	}

	group := cfg.Favorites["group-fav"]
	if group.Type != FavoriteTypeGroups {
		t.Errorf("group-fav type = %q, want %q", group.Type, FavoriteTypeGroups)
	}
	if group.Group != "SG-Dev" {
		t.Errorf("group-fav group = %q, want %q", group.Group, "SG-Dev")
	}
	if group.DirectoryID != "dir-xyz" {
		t.Errorf("group-fav directory_id = %q, want %q", group.DirectoryID, "dir-xyz")
	}

	legacy := cfg.Favorites["legacy-fav"]
	if legacy.Type != "" {
		t.Errorf("legacy-fav type = %q, want empty", legacy.Type)
	}
	if legacy.ResolvedType() != FavoriteTypeCloud {
		t.Errorf("legacy-fav ResolvedType() = %q, want %q", legacy.ResolvedType(), FavoriteTypeCloud)
	}
}

func TestLoadConfig_WithCacheTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte(`profile: my-profile
default_provider: azure
cache_ttl: 2h
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CacheTTL != "2h" {
		t.Errorf("cache_ttl = %q, want %q", cfg.CacheTTL, "2h")
	}
}

func TestLoadConfig_BackwardsCompat_NoCacheTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte(`profile: old-profile
default_provider: azure
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CacheTTL != "" {
		t.Errorf("cache_ttl = %q, want empty for legacy config", cfg.CacheTTL)
	}
}

func TestSaveConfig_CacheTTL_OmitsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := DefaultConfig()
	if err := Save(cfg, path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if strings.Contains(string(data), "cache_ttl") {
		t.Errorf("expected cache_ttl to be omitted when empty, got:\n%s", string(data))
	}
}

func TestParseCacheTTL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// value is the raw cache_ttl string.
		value string
		want  time.Duration
		// wantErrContains empty means the call must succeed. Every entry must
		// appear in the error: rejecting a value is only half the job, the
		// message must also say what a valid one looks like.
		wantErrContains []string
	}{
		{name: "empty uses default", value: "", want: DefaultCacheTTL},
		{name: "custom 2h", value: "2h", want: 2 * time.Hour},
		// Positive control: the guard below must not widen to swallow valid values.
		{name: "custom 30m", value: "30m", want: 30 * time.Minute},
		{
			name:  "unparseable is rejected with the expected syntax",
			value: "garbage",
			wantErrContains: []string{
				`invalid cache_ttl "garbage"`,
				"must be a positive Go duration such as 4h or 30m",
				// The wrapped time.ParseDuration error must survive.
				`time: invalid duration "garbage"`,
			},
		},
		{
			name:  "zero is rejected and names the --refresh alternative",
			value: "0s",
			wantErrContains: []string{
				`invalid cache_ttl "0s"`,
				"must be greater than zero",
				"use --refresh to bypass the cache for a single command",
			},
		},
		{
			name:  "negative is rejected and names the --refresh alternative",
			value: "-1h",
			wantErrContains: []string{
				`invalid cache_ttl "-1h"`,
				"must be greater than zero",
				"use --refresh to bypass the cache for a single command",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{CacheTTL: tt.value}
			got, err := ParseCacheTTL(cfg)

			if len(tt.wantErrContains) > 0 {
				if err == nil {
					t.Fatalf("ParseCacheTTL(%q) = %v, want error containing %q", tt.value, got, tt.wantErrContains)
				}
				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("ParseCacheTTL(%q) error = %q, want it to contain %q", tt.value, err, want)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseCacheTTL(%q) unexpected error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("ParseCacheTTL(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestParseCacheTTL_DefaultIsFourHours hardcodes the literal. Asserting
// `want: DefaultCacheTTL` restates the symbol under test and cannot detect a
// change to it.
func TestParseCacheTTL_DefaultIsFourHours(t *testing.T) {
	t.Parallel()
	got, err := ParseCacheTTL(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 4*time.Hour {
		t.Errorf("default cache TTL = %v, want 4h", got)
	}
}

// TestLoad_InvalidCacheTTLErrors pins that an unusable cache_ttl surfaces at
// config load, not later when some command happens to build a cache.
func TestLoad_InvalidCacheTTLErrors(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"garbage", "0s", "-1h"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.yaml")
			content := []byte("profile: p\ncache_ttl: " + value + "\n")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load() with cache_ttl %q = nil error, want a validation error", value)
			}
			if !strings.Contains(err.Error(), "cache_ttl") {
				t.Errorf("error = %q, want it to name cache_ttl", err)
			}
		})
	}
}

// TestLoad_PartialYAMLKeepsDefaults pins that a file setting only some keys
// leaves the rest at their defaults — dropping the DefaultConfig() seed would
// silently lose `profile: grant`.
func TestLoad_PartialYAMLKeepsDefaults(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	// Deliberately sets only default_provider.
	if err := os.WriteFile(path, []byte("default_provider: aws\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Profile != "grant" {
		t.Errorf("profile = %q, want the default %q to survive a partial file", cfg.Profile, "grant")
	}
	if cfg.DefaultProvider != "aws" {
		t.Errorf("default_provider = %q, want %q", cfg.DefaultProvider, "aws")
	}
}

// TestLoad_FavoritesNeverNil pins the nil-map backfill. `favorites:` with no
// value unmarshals to a nil map, and writing to a nil map panics.
func TestLoad_FavoritesNeverNil(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"explicit null":    "profile: p\nfavorites:\n",
		"no favorites key": "profile: p\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Favorites == nil {
				t.Fatal("Favorites is nil; a write to it would panic")
			}
			// Prove it is writable, which is the behavior that actually matters.
			cfg.Favorites["x"] = Favorite{Provider: "azure"}
		})
	}
}

// TestLoad_InvalidYAMLErrors pins that a malformed file is reported rather
// than silently yielding a half-populated config.
func TestLoad_InvalidYAMLErrors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("profile: [unterminated\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error for malformed YAML, want an error")
	}
	// Assert the parse error specifically. "did it error" would also be
	// satisfied by an unrelated failure — a read error, or the cache_ttl
	// validation that now also runs inside Load.
	if !strings.Contains(err.Error(), "yaml:") {
		t.Errorf("error = %q, want the YAML parse error", err)
	}
	if !strings.Contains(err.Error(), "did not find expected ',' or ']'") {
		t.Errorf("error = %q, want it to describe the unterminated sequence", err)
	}
}

// TestLoadDefaultWithPath_ErrorNamesTheFile pins that a load failure names the
// config file. With GRANT_CONFIG pointed somewhere non-default, naming only
// the offending value leaves the user with no idea which file to edit.
//
// Not parallel: sets GRANT_CONFIG for the process.
func TestLoadDefaultWithPath_ErrorNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-grant.yaml")
	if err := os.WriteFile(path, []byte("cache_ttl: garbage\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("GRANT_CONFIG", path)

	_, _, err := LoadDefaultWithPath()
	if err == nil {
		t.Fatal("LoadDefaultWithPath() = nil error, want the invalid cache_ttl reported")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name the config path %q", err, path)
	}
	if !strings.Contains(err.Error(), `invalid cache_ttl "garbage"`) {
		t.Errorf("error = %q, want it to name the offending value", err)
	}
	if !strings.Contains(err.Error(), "must be a positive Go duration such as 4h or 30m") {
		t.Errorf("error = %q, want it to say what a valid value looks like", err)
	}
	// The remedy is to edit the named file. `grant configure` rewrites the
	// config from scratch and drops favorites and default_provider, so the
	// error must never send the user there.
	if strings.Contains(err.Error(), "grant configure") {
		t.Errorf("error = %q, must not suggest `grant configure` as the remedy", err)
	}
}

// TestLoad_UnreadableIsNotTreatedAsMissing is the portable sibling of
// TestLoadConfig_PermissionError, which skips on Windows and so leaves Load's
// missing-vs-unreadable distinction with zero coverage on that CI leg. A
// directory read fails as EISDIR on POSIX and ERROR_ACCESS_DENIED on Windows,
// and is os.ErrNotExist on neither — so it drives the same branch everywhere.
func TestLoad_UnreadableIsNotTreatedAsMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if _, err := os.ReadFile(dir); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("premise broken: reading a directory reported ErrNotExist: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load(<directory>) = nil error, want a read error rather than the default config")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error = %q, want the read-error wrapping", err)
	}
}

// TestConfigDir_EndsInDotGrant pins the directory name users are told to look in.
func TestConfigDir_EndsInDotGrant(t *testing.T) {
	dir, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir() error = %v", err)
	}
	if filepath.Base(dir) != ".grant" {
		t.Errorf("ConfigDir() = %q, want its last element to be %q", dir, ".grant")
	}
}

// TestSave_FileAndDirModes pins the 0600/0700 modes. The config file holds no
// secrets today, but it is the sibling of the cache and profile directories
// and users reasonably expect it to be private.
func TestSave_FileAndDirModes(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Go synthesizes 0666/0777 for Windows files and os.Chmod there only toggles the read-only attribute, so POSIX mode bits carry no information")
	}
	dir := filepath.Join(t.TempDir(), "grantcfg")
	path := filepath.Join(dir, "config.yaml")

	if err := Save(DefaultConfig(), path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("config file mode = %#o, want 0600", got)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("config dir mode = %#o, want 0700", got)
	}
}

// TestSave_MkdirAllFailure pins that a directory-creation failure propagates.
// The failure is forced portably: a path component that is an existing regular
// file makes MkdirAll fail with ENOTDIR on both platforms. No Windows error
// code is involved — os.MkdirAll (os/path.go) stats the parent itself and
// synthesizes &PathError{Op: "mkdir", Err: syscall.ENOTDIR} in platform-
// independent Go. A hardcoded /dev/null/... path would not work — on Windows
// that is an ordinary writable location.
func TestSave_MkdirAllFailure(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	path := filepath.Join(blocker, "sub", "config.yaml")
	err := Save(DefaultConfig(), path)
	if err == nil {
		t.Fatal("Save() = nil error when the parent directory cannot be created")
	}

	// A bare "did it error" check is not enough: with the MkdirAll error
	// swallowed, the subsequent WriteFile fails for the same underlying
	// reason and Save still returns an error. Pinning the syscall op is what
	// proves the directory-creation error is the one that propagated.
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error = %v (%T), want an *fs.PathError", err, err)
	}
	if pathErr.Op != "mkdir" {
		t.Errorf("error op = %q, want %q — the MkdirAll failure must be the one reported", pathErr.Op, "mkdir")
	}
}
