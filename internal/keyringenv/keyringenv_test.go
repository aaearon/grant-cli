package keyringenv

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeFS builds a ReadFile func serving the given path->contents map.
// Paths absent from the map return an error (unreadable / missing).
func fakeFS(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if content, ok := files[name]; ok {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}
}

// fakeEnv builds a LookupEnv func from a map. Entries present in the map are
// "set" (even when their value is empty); absent keys are unset.
func fakeEnv(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestDetectorIsWSL(t *testing.T) {
	tests := []struct {
		name  string
		goos  string
		files map[string]string
		env   map[string]string
		want  bool
	}{
		{
			name:  "lowercase microsoft in /proc/version (the regression)",
			goos:  "linux",
			files: map[string]string{procVersionPath: "Linux version 6.18.33.2-microsoft-standard-WSL2 (root@builder) #1 SMP"},
			want:  true,
		},
		{
			name:  "uppercase Microsoft in /proc/version (WSL1)",
			goos:  "linux",
			files: map[string]string{procVersionPath: "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)"},
			want:  true,
		},
		{
			name:  "wsl token in /proc/version only",
			goos:  "linux",
			files: map[string]string{procVersionPath: "Linux version 5.15.0-WSL2-custom"},
			want:  true,
		},
		{
			name:  "osrelease only",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "5.15.0-microsoft-standard-WSL2"},
			want:  true,
		},
		{
			name: "WSL_DISTRO_NAME only",
			goos: "linux",
			env:  map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want: true,
		},
		{
			name: "WSL_INTEROP only",
			goos: "linux",
			env:  map[string]string{"WSL_INTEROP": "/run/WSL/424_interop"},
			want: true,
		},
		{
			name: "empty WSL_DISTRO_NAME is not a signal",
			goos: "linux",
			env:  map[string]string{"WSL_DISTRO_NAME": ""},
			want: false,
		},
		{
			name: "plain linux",
			goos: "linux",
			files: map[string]string{
				procVersionPath:   "Linux version 6.8.0-51-generic (buildd@lcy02)",
				procOSReleasePath: "6.8.0-51-generic",
			},
			want: false,
		},
		{
			name: "both proc files unreadable",
			goos: "linux",
			want: false,
		},
		{
			name:  "non-linux GOOS never reads /proc",
			goos:  "windows",
			files: map[string]string{procVersionPath: "microsoft"},
			env:   map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readCalled := false
			d := Detector{
				ReadFile: func(name string) ([]byte, error) {
					readCalled = true
					return fakeFS(tt.files)(name)
				},
				LookupEnv: fakeEnv(tt.env),
				GOOS:      tt.goos,
			}
			if got := d.IsWSL(); got != tt.want {
				t.Errorf("IsWSL() = %v, want %v", got, tt.want)
			}
			if tt.goos != "linux" && readCalled {
				t.Error("IsWSL() read /proc on non-linux GOOS; expected short-circuit")
			}
		})
	}
}

func TestDetectorApply(t *testing.T) {
	wslFiles := map[string]string{procVersionPath: "Linux version 6.18.33.2-microsoft-standard-WSL2"}
	plainFiles := map[string]string{procVersionPath: "Linux version 6.8.0-51-generic"}

	tests := []struct {
		name        string
		goos        string
		files       map[string]string
		env         map[string]string
		setenvErr   error
		wantApplied bool
		wantErr     bool
		wantSetenv  bool
		reasonHas   string
	}{
		{
			name:       "not linux is a no-op",
			goos:       "darwin",
			wantSetenv: false,
			reasonHas:  "not linux",
		},
		{
			name:       "explicit =1 is preserved",
			goos:       "linux",
			files:      wslFiles,
			env:        map[string]string{envVar: "1"},
			wantSetenv: false,
			reasonHas:  "already set",
		},
		{
			name:       "explicit =0 is preserved (any non-empty value forces basic keyring)",
			goos:       "linux",
			files:      wslFiles,
			env:        map[string]string{envVar: "0"},
			wantSetenv: false,
			reasonHas:  "already set",
		},
		{
			name:       "explicit =false is preserved",
			goos:       "linux",
			files:      wslFiles,
			env:        map[string]string{envVar: "false"},
			wantSetenv: false,
			reasonHas:  "already set",
		},
		{
			name:        "explicitly empty value on WSL is overwritten",
			goos:        "linux",
			files:       wslFiles,
			env:         map[string]string{envVar: ""},
			wantApplied: true,
			wantSetenv:  true,
			reasonHas:   "WSL detected",
		},
		{
			name:        "unset on WSL applies the override",
			goos:        "linux",
			files:       wslFiles,
			wantApplied: true,
			wantSetenv:  true,
			reasonHas:   "WSL detected",
		},
		{
			name:       "unset on plain linux does not apply",
			goos:       "linux",
			files:      plainFiles,
			wantSetenv: false,
			reasonHas:  "not WSL",
		},
		{
			name:       "explicitly empty value on plain linux is left alone",
			goos:       "linux",
			files:      plainFiles,
			env:        map[string]string{envVar: ""},
			wantSetenv: false,
			reasonHas:  "not WSL",
		},
		{
			name:       "setenv failure fails closed",
			goos:       "linux",
			files:      wslFiles,
			setenvErr:  errors.New("boom"),
			wantSetenv: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var setKey, setVal string
			setCalls := 0
			d := Detector{
				ReadFile:  fakeFS(tt.files),
				LookupEnv: fakeEnv(tt.env),
				Setenv: func(k, v string) error {
					setCalls++
					setKey, setVal = k, v
					return tt.setenvErr
				},
				GOOS: tt.goos,
			}

			applied, reason, err := d.Apply()

			if (err != nil) != tt.wantErr {
				t.Fatalf("Apply() error = %v, wantErr %v", err, tt.wantErr)
			}
			if applied != tt.wantApplied {
				t.Errorf("Apply() applied = %v, want %v", applied, tt.wantApplied)
			}
			if tt.wantSetenv && setCalls != 1 {
				t.Errorf("Setenv called %d times, want 1", setCalls)
			}
			if !tt.wantSetenv && setCalls != 0 {
				t.Errorf("Setenv called %d times, want 0", setCalls)
			}
			if tt.wantSetenv {
				if setKey != envVar || setVal != "1" {
					t.Errorf("Setenv(%q, %q), want (%q, %q)", setKey, setVal, envVar, "1")
				}
			}
			if tt.reasonHas != "" && !strings.Contains(reason, tt.reasonHas) {
				t.Errorf("reason = %q, want it to contain %q", reason, tt.reasonHas)
			}
		})
	}
}

func TestPackageApplyUsesRealDefaults(t *testing.T) {
	// Sanity: the package-level Apply must be wired to real os functions and
	// must not panic or error on this host.
	t.Setenv(envVar, "1")
	applied, reason, err := Apply()
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if applied {
		t.Error("Apply() applied = true, want false when the env var is already set")
	}
	// On linux the env-var check wins; on other platforms the GOOS guard does.
	if !strings.Contains(reason, "already set") && !strings.Contains(reason, "not linux") {
		t.Errorf("reason = %q, want it to mention the var is already set or a non-linux host", reason)
	}
}
