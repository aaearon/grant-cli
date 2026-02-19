package config

import (
	"testing"
)

func TestAddFavorite_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	cfg := DefaultConfig()

	err := RemoveFavorite(cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing favorite, got nil")
	}
}

func TestGetFavorite_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	cfg := DefaultConfig()

	_, err := GetFavorite(cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing favorite, got nil")
	}
}

func TestListFavorites_Sorted(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestAddFavorite_GroupFavorite(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	fav := Favorite{
		Type:        FavoriteTypeGroups,
		Provider:    "azure",
		Group:       "SG-Admin",
		DirectoryID: "dir-abc-123",
	}

	err := AddFavorite(cfg, "my-group", fav)
	if err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}

	got, ok := cfg.Favorites["my-group"]
	if !ok {
		t.Fatal("expected favorite 'my-group' to exist")
	}
	if got.Type != FavoriteTypeGroups {
		t.Errorf("type = %q, want %q", got.Type, FavoriteTypeGroups)
	}
	if got.Provider != "azure" {
		t.Errorf("provider = %q, want %q", got.Provider, "azure")
	}
	if got.Group != "SG-Admin" {
		t.Errorf("group = %q, want %q", got.Group, "SG-Admin")
	}
	if got.DirectoryID != "dir-abc-123" {
		t.Errorf("directory_id = %q, want %q", got.DirectoryID, "dir-abc-123")
	}
}

func TestGetFavorite_GroupFavorite(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	expected := Favorite{
		Type:        FavoriteTypeGroups,
		Provider:    "azure",
		Group:       "SG-Dev",
		DirectoryID: "dir-xyz",
	}
	cfg.Favorites["my-group"] = expected

	got, err := GetFavorite(cfg, "my-group")
	if err != nil {
		t.Fatalf("GetFavorite() error = %v", err)
	}

	if got.Type != expected.Type {
		t.Errorf("type = %q, want %q", got.Type, expected.Type)
	}
	if got.Provider != expected.Provider {
		t.Errorf("provider = %q, want %q", got.Provider, expected.Provider)
	}
	if got.Group != expected.Group {
		t.Errorf("group = %q, want %q", got.Group, expected.Group)
	}
	if got.DirectoryID != expected.DirectoryID {
		t.Errorf("directory_id = %q, want %q", got.DirectoryID, expected.DirectoryID)
	}
}

func TestListFavorites_MixedCloudAndGroups(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Favorites["cloud-fav"] = Favorite{
		Type:     FavoriteTypeCloud,
		Provider: "aws",
		Target:   "account-123",
		Role:     "Admin",
	}
	cfg.Favorites["group-fav"] = Favorite{
		Type:        FavoriteTypeGroups,
		Provider:    "azure",
		Group:       "SG-Admin",
		DirectoryID: "dir-abc",
	}

	entries := ListFavorites(cfg)
	if len(entries) != 2 {
		t.Fatalf("ListFavorites() length = %d, want 2", len(entries))
	}

	// Sorted alphabetically: cloud-fav, group-fav
	if entries[0].Name != "cloud-fav" {
		t.Errorf("entries[0].Name = %q, want %q", entries[0].Name, "cloud-fav")
	}
	if entries[0].Type != FavoriteTypeCloud {
		t.Errorf("entries[0].Type = %q, want %q", entries[0].Type, FavoriteTypeCloud)
	}
	if entries[1].Name != "group-fav" {
		t.Errorf("entries[1].Name = %q, want %q", entries[1].Name, "group-fav")
	}
	if entries[1].Type != FavoriteTypeGroups {
		t.Errorf("entries[1].Type = %q, want %q", entries[1].Type, FavoriteTypeGroups)
	}
	if entries[1].Group != "SG-Admin" {
		t.Errorf("entries[1].Group = %q, want %q", entries[1].Group, "SG-Admin")
	}
}

func TestResolvedType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		favType  string
		wantType string
	}{
		{name: "empty defaults to cloud", favType: "", wantType: FavoriteTypeCloud},
		{name: "explicit cloud", favType: FavoriteTypeCloud, wantType: FavoriteTypeCloud},
		{name: "explicit groups", favType: FavoriteTypeGroups, wantType: FavoriteTypeGroups},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fav := Favorite{Type: tt.favType}
			got := fav.ResolvedType()
			if got != tt.wantType {
				t.Errorf("ResolvedType() = %q, want %q", got, tt.wantType)
			}
		})
	}
}
