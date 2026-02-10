package main

import (
	"testing"
	"time"
)

func TestGenerateTOTP_ValidSecret(t *testing.T) {
	// Known TOTP secret (base32-encoded)
	secret := "JBSWY3DPEHPK3PXP"
	code, err := generateTOTP(secret)
	if err != nil {
		t.Fatalf("generateTOTP returned error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q (len=%d)", code, len(code))
	}
	// Verify it's all digits
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("expected numeric code, got %q", code)
			break
		}
	}
}

func TestGenerateTOTP_EmptySecret(t *testing.T) {
	_, err := generateTOTP("")
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

func TestGenerateTOTP_InvalidBase32(t *testing.T) {
	_, err := generateTOTP("!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base32 secret, got nil")
	}
}

func TestGenerateTOTP_Deterministic(t *testing.T) {
	// Two calls at the same time with the same secret should produce the same code
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Now()
	code1, err := generateTOTPAt(secret, now)
	if err != nil {
		t.Fatalf("generateTOTPAt returned error: %v", err)
	}
	code2, err := generateTOTPAt(secret, now)
	if err != nil {
		t.Fatalf("generateTOTPAt returned error: %v", err)
	}
	if code1 != code2 {
		t.Errorf("expected deterministic output, got %q and %q", code1, code2)
	}
}
