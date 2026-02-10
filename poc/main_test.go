package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// buildFakeJWT creates a JWT with the given claims (header and signature are placeholders).
func buildFakeJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + encodedPayload + ".fakesig"
}

func TestParseJWTClaims_SubdomainAndPlatformDomain(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{
		"subdomain":       "abz4452",
		"platform_domain": "cyberark.cloud",
		"unique_name":     "user@abz4452.id.cyberark.cloud",
	})

	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subdomain != "abz4452" {
		t.Errorf("expected subdomain=abz4452, got %s", claims.Subdomain)
	}
	if claims.PlatformDomain != "cyberark.cloud" {
		t.Errorf("expected platform_domain=cyberark.cloud, got %s", claims.PlatformDomain)
	}
	if claims.UniqueName != "user@abz4452.id.cyberark.cloud" {
		t.Errorf("expected unique_name, got %s", claims.UniqueName)
	}
}

func TestParseJWTClaims_ShellPrefixStripped(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{
		"subdomain":       "abz4452",
		"platform_domain": "shell.cyberark.cloud",
	})

	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.PlatformDomain != "cyberark.cloud" {
		t.Errorf("expected shell. prefix stripped, got %s", claims.PlatformDomain)
	}
}

func TestParseJWTClaims_FallbackToUniqueName(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{
		"unique_name": "admin@mytenant.cyberark.cloud",
	})

	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subdomain != "mytenant" {
		t.Errorf("expected subdomain=mytenant from unique_name fallback, got %s", claims.Subdomain)
	}
}

func TestParseJWTClaims_SubdomainTakesPriority(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{
		"subdomain":   "primary",
		"unique_name": "admin@fallback.cyberark.cloud",
	})

	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subdomain != "primary" {
		t.Errorf("expected subdomain=primary (from claim, not unique_name), got %s", claims.Subdomain)
	}
}

func TestParseJWTClaims_NoClaims(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{})

	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subdomain != "" {
		t.Errorf("expected empty subdomain, got %s", claims.Subdomain)
	}
	if claims.PlatformDomain != "" {
		t.Errorf("expected empty platform_domain, got %s", claims.PlatformDomain)
	}
}

func TestParseJWTClaims_InvalidJWT(t *testing.T) {
	_, err := parseJWTClaims("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestParseJWTClaims_InvalidBase64(t *testing.T) {
	_, err := parseJWTClaims("header.!!!invalid!!!.sig")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://abz4452.id.cyberark.cloud", "abz4452"},
		{"http://tenant.id.cyberark.cloud", "tenant"},
		{"abz4452.id.cyberark.cloud", "abz4452"},
	}
	for _, tt := range tests {
		got := extractSubdomain(tt.url)
		if got != tt.want {
			t.Errorf("extractSubdomain(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestExtractPlatformDomain(t *testing.T) {
	tests := []struct {
		url       string
		subdomain string
		want      string
	}{
		{"https://abz4452.id.cyberark.cloud", "abz4452", "cyberark.cloud"},
		{"https://tenant.cyberark.cloud", "tenant", "cyberark.cloud"},
	}
	for _, tt := range tests {
		got := extractPlatformDomain(tt.url, tt.subdomain)
		if got != tt.want {
			t.Errorf("extractPlatformDomain(%q, %q) = %q, want %q", tt.url, tt.subdomain, got, tt.want)
		}
	}
}
