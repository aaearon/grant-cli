package config

import (
	"fmt"
	"sort"
)

// FavoriteEntry pairs a favorite name with its data, used for sorted listing.
type FavoriteEntry struct {
	Name string
	Favorite
}

// AddFavorite adds a named favorite to the config. Returns an error if the name
// already exists. Defaults provider to "azure" if empty.
func AddFavorite(cfg *Config, name string, fav Favorite) error {
	if _, exists := cfg.Favorites[name]; exists {
		return fmt.Errorf("favorite %q already exists", name)
	}

	if fav.Provider == "" {
		fav.Provider = "azure"
	}

	cfg.Favorites[name] = fav
	return nil
}

// RemoveFavorite removes a named favorite. Returns an error if not found.
func RemoveFavorite(cfg *Config, name string) error {
	if _, exists := cfg.Favorites[name]; !exists {
		return fmt.Errorf("favorite %q not found", name)
	}

	delete(cfg.Favorites, name)
	return nil
}

// GetFavorite retrieves a favorite by name. Returns an error if not found.
func GetFavorite(cfg *Config, name string) (Favorite, error) {
	fav, exists := cfg.Favorites[name]
	if !exists {
		return Favorite{}, fmt.Errorf("favorite %q not found", name)
	}
	return fav, nil
}

// ListFavorites returns all favorites sorted alphabetically by name.
func ListFavorites(cfg *Config) []FavoriteEntry {
	entries := make([]FavoriteEntry, 0, len(cfg.Favorites))
	for name, fav := range cfg.Favorites {
		entries = append(entries, FavoriteEntry{Name: name, Favorite: fav})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries
}
