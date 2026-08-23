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
	Type        string `yaml:"type,omitempty"         json:"type,omitempty"`
	Provider    string `yaml:"provider"               json:"provider"`
	Target      string `yaml:"target"                 json:"target"`
	Role        string `yaml:"role"                   json:"role"`
	Group       string `yaml:"group,omitempty"        json:"group,omitempty"`
	DirectoryID string `yaml:"directory_id,omitempty" json:"directoryId,omitempty"`
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

	// Validate here so an unusable cache_ttl surfaces at load rather than
	// later, when some command happens to build a cache.
	if _, err := ParseCacheTTL(cfg); err != nil {
		return nil, err
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
		// Name the file: with GRANT_CONFIG set, the value alone leaves the
		// user guessing which config to edit.
		return nil, "", fmt.Errorf("failed to load config %s: %w", cfgPath, err)
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
//
// An absent value means "use the default". Any explicitly supplied value that
// cannot serve as a TTL — unparseable, zero or negative — is an error. The two
// are deliberately treated the same way: silently defaulting one while
// rejecting the other would validate a single field by two opposite rules.
func ParseCacheTTL(cfg *Config) (time.Duration, error) {
	if cfg.CacheTTL == "" {
		return DefaultCacheTTL, nil
	}
	d, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		return 0, fmt.Errorf("invalid cache_ttl %q: must be a positive Go duration such as 4h or 30m: %w", cfg.CacheTTL, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid cache_ttl %q: must be greater than zero; remove the setting to use the default (%s)", cfg.CacheTTL, DefaultCacheTTL)
	}
	return d, nil
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
