package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Favorite represents a saved elevation target.
type Favorite struct {
	Provider string `yaml:"provider"`
	Target   string `yaml:"target"`
	Role     string `yaml:"role"`
}

// Config holds the sca-cli application configuration.
type Config struct {
	Profile         string              `yaml:"profile"`
	DefaultProvider string              `yaml:"default_provider"`
	Favorites       map[string]Favorite `yaml:"favorites"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Profile:         "sca-cli",
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
		return DefaultConfig(), nil
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// ConfigDir returns the default config directory path.
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sca-cli")
}

// ConfigPath returns the config file path, respecting the SCA_CLI_CONFIG env var.
func ConfigPath() string {
	if p := os.Getenv("SCA_CLI_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "config.yaml")
}
