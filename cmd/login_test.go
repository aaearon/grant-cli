package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

func TestLoginCommand(t *testing.T) {
	tests := []struct {
		name        string
		setupAuth   func() authenticator
		wantContain []string
		wantErr     bool
	}{
		{
			name: "successful authentication",
			setupAuth: func() authenticator {
				expiresIn := commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour))
				return &mockAuthenticator{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt-token",
						Username:  "test.user@example.com",
						ExpiresIn: expiresIn,
					},
					authErr: nil,
				}
			},
			wantContain: []string{
				"Successfully authenticated",
				"test.user@example.com",
				"expires",
			},
			wantErr: false,
		},
		{
			name: "authentication failure",
			setupAuth: func() authenticator {
				return &mockAuthenticator{
					token:   nil,
					authErr: errors.New("invalid credentials"),
				}
			},
			wantContain: []string{
				"authentication failed",
				"invalid credentials",
			},
			wantErr: true,
		},
		{
			name: "authentication failure - user cancelled",
			setupAuth: func() authenticator {
				return &mockAuthenticator{
					token:   nil,
					authErr: errors.New("user cancelled"),
				}
			},
			wantContain: []string{
				"authentication failed",
				"user cancelled",
			},
			wantErr: true,
		},
		{
			name: "token with no expiry",
			setupAuth: func() authenticator {
				return &mockAuthenticator{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt-token",
						Username:  "test.user@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time{},
					},
					authErr: nil,
				}
			},
			wantContain: []string{
				"Successfully authenticated",
				"test.user@example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: Create a temporary profile so auto-configure doesn't trigger
			tempDir := t.TempDir()
			t.Setenv("IDSEC_PROFILES_FOLDER", tempDir)

			// Create a minimal profile file
			profile := &models.IdsecProfile{
				ProfileName: "grant",
				AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
					"isp": {
						Username:   "test.user@example.com",
						AuthMethod: authmodels.Identity,
						AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{
							IdentityURL:            "https://example.cyberark.cloud",
							IdentityMFAMethod:      "",
							IdentityMFAInteractive: true,
						},
					},
				},
			}

			// Save profile to temp directory
			loader := &profiles.FileSystemProfilesLoader{}
			if err := loader.SaveProfile(profile); err != nil {
				t.Fatalf("failed to create test profile: %v", err)
			}

			// Create command with mock authenticator
			cmd := NewLoginCommandWithAuth(tt.setupAuth())

			// Execute command
			output, err := executeCommand(cmd)

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Verify output contains expected strings
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestLoginCommandIntegration(t *testing.T) {
	// Test that login command is properly registered
	rootCmd := newTestRootCommand()
	loginCmd := NewLoginCommand()
	rootCmd.AddCommand(loginCmd)

	// Verify command is accessible
	cmd, _, err := rootCmd.Find([]string{"login"})
	if err != nil {
		t.Fatalf("login command not found: %v", err)
	}

	if cmd.Use != "login" {
		t.Errorf("expected command Use='login', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected command to have Short description")
	}
}

func TestLoginCommandUsage(t *testing.T) {
	cmd := NewLoginCommand()

	// Verify command metadata
	if cmd.Use != "login" {
		t.Errorf("expected Use='login', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}
}

func TestLoginCommandAutoConfigure(t *testing.T) {
	// Placeholder test — auto-configure DI not yet wired
	t.Skip("Auto-configure not yet implemented")
}
