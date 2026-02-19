package config

import (
	"os"
	"path/filepath"
	"testing"
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
	if err := os.WriteFile(path, content, 0644); err != nil {
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
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Create a file, then make it unreadable
	if err := os.WriteFile(path, []byte("profile: test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0644) })

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
	if err := os.WriteFile(path, content, 0644); err != nil {
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
	if err := os.WriteFile(path, content, 0644); err != nil {
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
