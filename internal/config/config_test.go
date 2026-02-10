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

	if cfg.Profile != "sca-cli" {
		t.Errorf("profile = %q, want %q", cfg.Profile, "sca-cli")
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

func TestConfigPath_Override(t *testing.T) {
	customPath := "/tmp/custom-sca-cli/config.yaml"

	t.Setenv("SCA_CLI_CONFIG", customPath)

	got := ConfigPath()
	if got != customPath {
		t.Errorf("ConfigPath() = %q, want %q", got, customPath)
	}
}
