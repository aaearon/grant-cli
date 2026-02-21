// Package config manages grant application configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	FavoriteTypeCloud  = "cloud"
	FavoriteTypeGroups = "groups"
)

// DefaultCacheTTL is the default eligibility cache TTL.
const DefaultCacheTTL = 4 * time.Hour

// Favorite represents a saved elevation target.
type Favorite struct {
	Type        string `yaml:"type,omitempty"`         // "cloud" or "groups"; empty → "cloud"
	Provider    string `yaml:"provider"`
	Target      string `yaml:"target"`
	Role        string `yaml:"role"`
	Group       string `yaml:"group,omitempty"`        // Group name (groups only)
	DirectoryID string `yaml:"directory_id,omitempty"` // Directory ID (groups only)
}

// Config holds the grant application configuration.
type Config struct {
	Profile         string              `yaml:"profile"`
	DefaultProvider string              `yaml:"default_provider"`
	CacheTTL        string              `yaml:"cache_ttl,omitempty"`
	Favorites       map[string]Favorite `yaml:"favorites"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Profile:         "grant",
		DefaultProvider: "azure",
		Favorites:       make(map[string]Favorite),
	}
}

// Load reads a config file from the given path. If the file does not exist,
// it returns the default config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Favorites == nil {
		cfg.Favorites = make(map[string]Favorite)
	}

	return cfg, nil
}

// Save writes a config to the given path, creating parent directories as needed.
func Save(cfg *Config, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// LoadDefaultWithPath resolves the config path via ConfigPath() and loads the config.
// Returns the config, the resolved path, and any error.
func LoadDefaultWithPath() (*Config, string, error) {
	cfgPath, err := ConfigPath()
	if err != nil {
		return nil, "", fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}
	return cfg, cfgPath, nil
}

// ConfigDir returns the default config directory path.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine home directory: %w", err)
	}
	return filepath.Join(home, ".grant"), nil
}

// ParseCacheTTL returns the configured cache TTL duration.
// Falls back to DefaultCacheTTL if the config value is empty or unparseable.
func ParseCacheTTL(cfg *Config) time.Duration {
	if cfg.CacheTTL == "" {
		return DefaultCacheTTL
	}
	d, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		return DefaultCacheTTL
	}
	return d
}

// ConfigPath returns the config file path, respecting the GRANT_CONFIG env var.
func ConfigPath() (string, error) {
	if p := os.Getenv("GRANT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}
