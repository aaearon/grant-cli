package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaearon/sca-cli/internal/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// mockProfileSaver implements profileSaver interface for testing
type mockProfileSaver struct {
	saveFunc func(*models.IdsecProfile) error
	saveErr  error
}

func (m *mockProfileSaver) SaveProfile(profile *models.IdsecProfile) error {
	if m.saveFunc != nil {
		return m.saveFunc(profile)
	}
	return m.saveErr
}

func TestConfigureCommand(t *testing.T) {
	tests := []struct {
		name          string
		tenantURL     string
		username      string
		mfaMethod     string
		setupSaver    func() profileSaver
		setupConfigFn func() (string, error)
		wantContain   []string
		wantErr       bool
	}{
		{
			name:      "successful configure with all fields",
			tenantURL: "https://example.cyberark.cloud",
			username:  "test.user@example.com",
			mfaMethod: "otp",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{
					saveFunc: func(p *models.IdsecProfile) error {
						// Verify profile structure
						if p.ProfileName != "sca-cli" {
							t.Errorf("expected ProfileName='sca-cli', got %q", p.ProfileName)
						}
						if p.AuthProfiles == nil {
							t.Error("expected AuthProfiles to be initialized")
						}
						if authProfile, ok := p.AuthProfiles["isp"]; !ok {
							t.Error("expected 'isp' auth profile to exist")
						} else {
							if authProfile.Username != "test.user@example.com" {
								t.Errorf("expected Username='test.user@example.com', got %q", authProfile.Username)
							}
							if authProfile.AuthMethod != auth_models.Identity {
								t.Errorf("expected AuthMethod=%q, got %q", auth_models.Identity, authProfile.AuthMethod)
							}
							if settings, ok := authProfile.AuthMethodSettings.(*auth_models.IdentityIdsecAuthMethodSettings); !ok {
								t.Error("expected IdentityIdsecAuthMethodSettings type")
							} else {
								if settings.IdentityURL != "https://example.cyberark.cloud" {
									t.Errorf("expected IdentityURL='https://example.cyberark.cloud', got %q", settings.IdentityURL)
								}
								if settings.IdentityMFAMethod != "otp" {
									t.Errorf("expected IdentityMFAMethod='otp', got %q", settings.IdentityMFAMethod)
								}
								if !settings.IdentityMFAInteractive {
									t.Error("expected IdentityMFAInteractive=true")
								}
							}
						}
						return nil
					},
				}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"Profile saved to",
				"sca-cli.json",
				"Config saved to",
				"config.yaml",
			},
			wantErr: false,
		},
		{
			name:      "successful configure with blank MFA method",
			tenantURL: "https://example.cyberark.cloud",
			username:  "test.user@example.com",
			mfaMethod: "",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{
					saveFunc: func(p *models.IdsecProfile) error {
						if authProfile, ok := p.AuthProfiles["isp"]; ok {
							if settings, ok := authProfile.AuthMethodSettings.(*auth_models.IdentityIdsecAuthMethodSettings); ok {
								if settings.IdentityMFAMethod != "" {
									t.Errorf("expected IdentityMFAMethod='', got %q", settings.IdentityMFAMethod)
								}
								if !settings.IdentityMFAInteractive {
									t.Error("expected IdentityMFAInteractive=true for blank MFA method")
								}
							}
						}
						return nil
					},
				}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"Profile saved to",
				"Config saved to",
			},
			wantErr: false,
		},
		{
			name:      "invalid tenant URL",
			tenantURL: "not-a-valid-url",
			username:  "test.user@example.com",
			mfaMethod: "otp",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"invalid tenant URL",
			},
			wantErr: true,
		},
		{
			name:      "empty username",
			tenantURL: "https://example.cyberark.cloud",
			username:  "",
			mfaMethod: "otp",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"username is required",
			},
			wantErr: true,
		},
		{
			name:      "invalid MFA method",
			tenantURL: "https://example.cyberark.cloud",
			username:  "test.user@example.com",
			mfaMethod: "invalid",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"invalid MFA method",
				"otp",
				"oath",
				"sms",
				"email",
				"pf",
			},
			wantErr: true,
		},
		{
			name:      "profile save error",
			tenantURL: "https://example.cyberark.cloud",
			username:  "test.user@example.com",
			mfaMethod: "otp",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{
					saveErr: os.ErrPermission,
				}
			},
			setupConfigFn: func() (string, error) {
				tmpDir := t.TempDir()
				cfgPath := filepath.Join(tmpDir, "config.yaml")
				return cfgPath, nil
			},
			wantContain: []string{
				"failed to save profile",
			},
			wantErr: true,
		},
		{
			name:      "config save error",
			tenantURL: "https://example.cyberark.cloud",
			username:  "test.user@example.com",
			mfaMethod: "otp",
			setupSaver: func() profileSaver {
				return &mockProfileSaver{
					saveFunc: func(p *models.IdsecProfile) error {
						return nil
					},
				}
			},
			setupConfigFn: func() (string, error) {
				// Return a path in a non-existent directory with restricted permissions
				return "/dev/null/config.yaml", nil
			},
			wantContain: []string{
				"failed to save config",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup config path
			cfgPath, err := tt.setupConfigFn()
			if err != nil {
				t.Fatalf("failed to setup config path: %v", err)
			}

			// Override environment variable for config path
			t.Setenv("SCA_CLI_CONFIG", cfgPath)

			// Create command with mock dependencies
			cmd := NewConfigureCommandWithDeps(tt.setupSaver(), tt.tenantURL, tt.username, tt.mfaMethod)

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

			// Verify config file was created for success cases
			if !tt.wantErr {
				if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
					t.Errorf("config file was not created at %s", cfgPath)
				} else {
					// Verify config contents
					cfg, err := config.Load(cfgPath)
					if err != nil {
						t.Errorf("failed to load config: %v", err)
					}
					if cfg.Profile != "sca-cli" {
						t.Errorf("expected Profile='sca-cli', got %q", cfg.Profile)
					}
					if cfg.DefaultProvider != "azure" {
						t.Errorf("expected DefaultProvider='azure', got %q", cfg.DefaultProvider)
					}
					if cfg.Favorites == nil {
						t.Error("expected Favorites to be initialized")
					}
				}
			}
		})
	}
}

func TestConfigureCommandIntegration(t *testing.T) {
	// Test that configure command is properly registered
	rootCmd := NewRootCommand()
	configureCmd := NewConfigureCommand()
	rootCmd.AddCommand(configureCmd)

	// Verify command is accessible
	cmd, _, err := rootCmd.Find([]string{"configure"})
	if err != nil {
		t.Fatalf("configure command not found: %v", err)
	}

	if cmd.Use != "configure" {
		t.Errorf("expected command Use='configure', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected command to have Short description")
	}
}

func TestConfigureCommandUsage(t *testing.T) {
	cmd := NewConfigureCommand()

	// Verify command metadata
	if cmd.Use != "configure" {
		t.Errorf("expected Use='configure', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}
}

func TestValidateTenantURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid HTTPS URL",
			url:     "https://example.cyberark.cloud",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with port",
			url:     "https://example.cyberark.cloud:8443",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with path",
			url:     "https://example.cyberark.cloud/path",
			wantErr: false,
		},
		{
			name:    "HTTP URL should fail",
			url:     "http://example.cyberark.cloud",
			wantErr: true,
		},
		{
			name:    "invalid URL format",
			url:     "not-a-url",
			wantErr: true,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "URL without scheme",
			url:     "example.cyberark.cloud",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTenantURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMFAMethod(t *testing.T) {
	tests := []struct {
		name      string
		mfaMethod string
		wantErr   bool
	}{
		{
			name:      "valid otp",
			mfaMethod: "otp",
			wantErr:   false,
		},
		{
			name:      "valid oath",
			mfaMethod: "oath",
			wantErr:   false,
		},
		{
			name:      "valid sms",
			mfaMethod: "sms",
			wantErr:   false,
		},
		{
			name:      "valid email",
			mfaMethod: "email",
			wantErr:   false,
		},
		{
			name:      "valid pf",
			mfaMethod: "pf",
			wantErr:   false,
		},
		{
			name:      "empty is valid",
			mfaMethod: "",
			wantErr:   false,
		},
		{
			name:      "invalid method",
			mfaMethod: "invalid",
			wantErr:   true,
		},
		{
			name:      "case sensitive - OTP should fail",
			mfaMethod: "OTP",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMFAMethod(tt.mfaMethod)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMFAMethod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
