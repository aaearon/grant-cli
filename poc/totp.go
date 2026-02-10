package main

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// generateTOTP generates a 6-digit TOTP code from the given base32-encoded secret.
func generateTOTP(secret string) (string, error) {
	return generateTOTPAt(secret, time.Now())
}

// generateTOTPAt generates a 6-digit TOTP code for a specific point in time.
func generateTOTPAt(secret string, t time.Time) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("TOTP secret cannot be empty")
	}
	code, err := totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}
