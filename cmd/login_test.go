package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	common_models "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// mockAuthenticator implements the subset of auth.IdsecAuth we need for testing
type mockAuthenticator struct {
	authenticateFunc func(profile *models.IdsecProfile, authProfile *auth_models.IdsecAuthProfile, secret *auth_models.IdsecSecret, force bool, refreshAuth bool) (*auth_models.IdsecToken, error)
	token            *auth_models.IdsecToken
	authErr          error
}

func (m *mockAuthenticator) Authenticate(profile *models.IdsecProfile, authProfile *auth_models.IdsecAuthProfile, secret *auth_models.IdsecSecret, force bool, refreshAuth bool) (*auth_models.IdsecToken, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(profile, authProfile, secret, force, refreshAuth)
	}
	return m.token, m.authErr
}

// mockProfileLoader implements the profileLoader interface for testing
type mockProfileLoader struct {
	loadFunc func(string) (*models.IdsecProfile, error)
	profile  *models.IdsecProfile
	loadErr  error
}

func (m *mockProfileLoader) LoadProfile(name string) (*models.IdsecProfile, error) {
	if m.loadFunc != nil {
		return m.loadFunc(name)
	}
	return m.profile, m.loadErr
}

// mockConfigureRunner mocks the configure flow for testing
type mockConfigureRunner struct {
	runFunc func() error
	runErr  error
}

func (m *mockConfigureRunner) runConfigure() error {
	if m.runFunc != nil {
		return m.runFunc()
	}
	return m.runErr
}

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
				expiresIn := common_models.IdsecRFC3339Time(time.Now().Add(1 * time.Hour))
				return &mockAuthenticator{
					token: &auth_models.IdsecToken{
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
					token: &auth_models.IdsecToken{
						Token:     "test-jwt-token",
						Username:  "test.user@example.com",
						ExpiresIn: common_models.IdsecRFC3339Time{},
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
				ProfileName: "sca-cli",
				AuthProfiles: map[string]*auth_models.IdsecAuthProfile{
					"isp": {
						Username:   "test.user@example.com",
						AuthMethod: auth_models.Identity,
						AuthMethodSettings: &auth_models.IdentityIdsecAuthMethodSettings{
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
	rootCmd := NewRootCommand()
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
	tests := []struct {
		name            string
		setupLoader     func() *mockProfileLoader
		setupAuth       func() authenticator
		setupConfigurer func() *mockConfigureRunner
		wantContain     []string
		wantErr         bool
	}{
		{
			name: "first time login - no profile exists, configure succeeds",
			setupLoader: func() *mockProfileLoader {
				// First call returns nil (no profile), second call returns profile
				callCount := 0
				return &mockProfileLoader{
					loadFunc: func(name string) (*models.IdsecProfile, error) {
						callCount++
						if callCount == 1 {
							return nil, nil // No profile on first call
						}
						// Return valid profile on second call (after configure)
						return &models.IdsecProfile{
							ProfileName: "sca-cli",
							AuthProfiles: map[string]*auth_models.IdsecAuthProfile{
								"isp": {
									Username:   "test.user@example.com",
									AuthMethod: auth_models.Identity,
								},
							},
						}, nil
					},
				}
			},
			setupAuth: func() authenticator {
				expiresIn := common_models.IdsecRFC3339Time(time.Now().Add(1 * time.Hour))
				return &mockAuthenticator{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt-token",
						Username:  "test.user@example.com",
						ExpiresIn: expiresIn,
					},
					authErr: nil,
				}
			},
			setupConfigurer: func() *mockConfigureRunner {
				return &mockConfigureRunner{
					runErr: nil, // Configure succeeds
				}
			},
			wantContain: []string{
				"No configuration found",
				"Successfully authenticated",
				"test.user@example.com",
			},
			wantErr: false,
		},
		{
			name: "first time login - profile exists",
			setupLoader: func() *mockProfileLoader {
				return &mockProfileLoader{
					profile: &models.IdsecProfile{
						ProfileName: "sca-cli",
						AuthProfiles: map[string]*auth_models.IdsecAuthProfile{
							"isp": {
								Username:   "test.user@example.com",
								AuthMethod: auth_models.Identity,
							},
						},
					},
					loadErr: nil,
				}
			},
			setupAuth: func() authenticator {
				expiresIn := common_models.IdsecRFC3339Time(time.Now().Add(1 * time.Hour))
				return &mockAuthenticator{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt-token",
						Username:  "test.user@example.com",
						ExpiresIn: expiresIn,
					},
					authErr: nil,
				}
			},
			setupConfigurer: func() *mockConfigureRunner {
				return &mockConfigureRunner{
					runErr: nil,
				}
			},
			wantContain: []string{
				"Successfully authenticated",
				"test.user@example.com",
			},
			wantErr: false,
		},
		{
			name: "first time login - configure fails",
			setupLoader: func() *mockProfileLoader {
				return &mockProfileLoader{
					profile: nil,
					loadErr: nil, // No error, just no profile
				}
			},
			setupAuth: func() authenticator {
				return &mockAuthenticator{
					token:   nil,
					authErr: nil,
				}
			},
			setupConfigurer: func() *mockConfigureRunner {
				return &mockConfigureRunner{
					runErr: errors.New("user cancelled configure"),
				}
			},
			wantContain: []string{
				"No configuration found",
				"user cancelled configure",
			},
			wantErr: true,
		},
		{
			name: "first time login - profile load error",
			setupLoader: func() *mockProfileLoader {
				return &mockProfileLoader{
					profile: nil,
					loadErr: errors.New("permission denied"),
				}
			},
			setupAuth: func() authenticator {
				return &mockAuthenticator{
					token:   nil,
					authErr: nil,
				}
			},
			setupConfigurer: func() *mockConfigureRunner {
				return &mockConfigureRunner{
					runErr: nil,
				}
			},
			wantContain: []string{
				"failed to load profile",
				"permission denied",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a placeholder test - the actual implementation will be done in task #5
			// For now, we're just defining the test structure
			t.Skip("Auto-configure not yet implemented")
		})
	}
}
