package config

import (
	"testing"
)

func TestAddFavorite_Success(t *testing.T) {
	cfg := DefaultConfig()
	fav := Favorite{Provider: "azure", Target: "sub-123", Role: "Owner"}

	err := AddFavorite(cfg, "prod-admin", fav)
	if err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}

	got, ok := cfg.Favorites["prod-admin"]
	if !ok {
		t.Fatal("expected favorite 'prod-admin' to exist")
	}
	if got.Provider != "azure" {
		t.Errorf("provider = %q, want %q", got.Provider, "azure")
	}
	if got.Target != "sub-123" {
		t.Errorf("target = %q, want %q", got.Target, "sub-123")
	}
	if got.Role != "Owner" {
		t.Errorf("role = %q, want %q", got.Role, "Owner")
	}
}

func TestAddFavorite_Duplicate(t *testing.T) {
	cfg := DefaultConfig()
	fav := Favorite{Provider: "azure", Target: "sub-123", Role: "Owner"}

	if err := AddFavorite(cfg, "prod-admin", fav); err != nil {
		t.Fatalf("first AddFavorite() error = %v", err)
	}

	err := AddFavorite(cfg, "prod-admin", fav)
	if err == nil {
		t.Fatal("expected error for duplicate favorite, got nil")
	}
}

func TestRemoveFavorite_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Favorites["prod-admin"] = Favorite{Provider: "azure", Target: "sub-123", Role: "Owner"}

	err := RemoveFavorite(cfg, "prod-admin")
	if err != nil {
		t.Fatalf("RemoveFavorite() error = %v", err)
	}

	if _, ok := cfg.Favorites["prod-admin"]; ok {
		t.Fatal("expected favorite 'prod-admin' to be removed")
	}
}

func TestRemoveFavorite_NotFound(t *testing.T) {
	cfg := DefaultConfig()

	err := RemoveFavorite(cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing favorite, got nil")
	}
}

func TestGetFavorite_Success(t *testing.T) {
	cfg := DefaultConfig()
	expected := Favorite{Provider: "azure", Target: "sub-123", Role: "Owner"}
	cfg.Favorites["prod-admin"] = expected

	got, err := GetFavorite(cfg, "prod-admin")
	if err != nil {
		t.Fatalf("GetFavorite() error = %v", err)
	}

	if got.Provider != expected.Provider {
		t.Errorf("provider = %q, want %q", got.Provider, expected.Provider)
	}
	if got.Target != expected.Target {
		t.Errorf("target = %q, want %q", got.Target, expected.Target)
	}
	if got.Role != expected.Role {
		t.Errorf("role = %q, want %q", got.Role, expected.Role)
	}
}

func TestGetFavorite_NotFound(t *testing.T) {
	cfg := DefaultConfig()

	_, err := GetFavorite(cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing favorite, got nil")
	}
}

func TestListFavorites_Sorted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Favorites["charlie"] = Favorite{Provider: "azure", Target: "sub-3", Role: "Reader"}
	cfg.Favorites["alpha"] = Favorite{Provider: "azure", Target: "sub-1", Role: "Owner"}
	cfg.Favorites["bravo"] = Favorite{Provider: "aws", Target: "acct-2", Role: "Admin"}

	entries := ListFavorites(cfg)
	if len(entries) != 3 {
		t.Fatalf("ListFavorites() length = %d, want 3", len(entries))
	}

	expectedOrder := []string{"alpha", "bravo", "charlie"}
	for i, want := range expectedOrder {
		if entries[i].Name != want {
			t.Errorf("entries[%d].Name = %q, want %q", i, entries[i].Name, want)
		}
	}
}

func TestListFavorites_Empty(t *testing.T) {
	cfg := DefaultConfig()

	entries := ListFavorites(cfg)
	if entries == nil {
		t.Fatal("ListFavorites() should return non-nil empty slice")
	}
	if len(entries) != 0 {
		t.Errorf("ListFavorites() length = %d, want 0", len(entries))
	}
}

func TestAddFavorite_DefaultProvider(t *testing.T) {
	cfg := DefaultConfig()
	fav := Favorite{Provider: "", Target: "sub-123", Role: "Owner"}

	err := AddFavorite(cfg, "my-fav", fav)
	if err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}

	got, ok := cfg.Favorites["my-fav"]
	if !ok {
		t.Fatal("expected favorite 'my-fav' to exist")
	}
	if got.Provider != "azure" {
		t.Errorf("provider = %q, want %q (should default to 'azure')", got.Provider, "azure")
	}
}
