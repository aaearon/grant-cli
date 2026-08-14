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

// fakeExists builds an Exists func that reports true only for the given paths.
func fakeExists(paths ...string) func(string) bool {
	return func(path string) bool {
		for _, p := range paths {
			if p == path {
				return true
			}
		}
		return false
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
		name   string
		goos   string
		files  map[string]string
		exists []string
		env    map[string]string
		want   bool
		// wantSignal, when set, pins which signal wslSignal reports. It is what
		// locks the documented precedence order; asserting only the boolean would
		// let the order silently change.
		wantSignal string
	}{
		{
			// Every signal present at once: /run/WSL must win.
			name:       "precedence: /run/WSL beats everything",
			goos:       "linux",
			files:      map[string]string{procOSReleasePath: "6.18.33.2-microsoft-standard-WSL2"},
			exists:     []string{runWSLPath, wslInteropPath},
			env:        map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04", "WSL_INTEROP": "/run/WSL/424_interop"},
			want:       true,
			wantSignal: runWSLPath,
		},
		{
			name:       "precedence: WSLInterop beats osrelease",
			goos:       "linux",
			files:      map[string]string{procOSReleasePath: "6.18.33.2-microsoft-standard-WSL2"},
			exists:     []string{wslInteropPath},
			env:        map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want:       true,
			wantSignal: wslInteropPath,
		},
		{
			name:       "precedence: osrelease is the last signal",
			goos:       "linux",
			files:      map[string]string{procOSReleasePath: "6.18.33.2-microsoft-standard-WSL2"},
			env:        map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want:       true,
			wantSignal: procOSReleasePath,
		},
		{
			// Verbatim osrelease from the WSL2 host that exposed the bug. It carries
			// both tokens, so it proves the end-to-end regression is caught but not
			// which token did it — the isolated cases below do that.
			name:  "real WSL2 osrelease (the regression)",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "6.18.33.2-microsoft-standard-WSL2\n"},
			want:  true,
		},
		{
			// The case /run/WSL exists for. A custom kernel (microsoft/WSL#6911)
			// carries neither token; interop disabled in wsl.conf drops the WSL1
			// binfmt registration and unsets WSL_INTEROP; and under sudo, a systemd
			// unit or cron the WSL_* env vars are gone too. WSL's init creates
			// /run/WSL regardless of all three, so it must still carry detection.
			name:   "/run/WSL alone: custom kernel, interop disabled, no env vars",
			goos:   "linux",
			files:  map[string]string{procOSReleasePath: "6.6.0-custom"},
			exists: []string{runWSLPath},
			want:   true,
		},
		{
			name:   "WSLInterop binfmt marker alone",
			goos:   "linux",
			exists: []string{wslInteropPath},
			want:   true,
		},
		{
			// WSL1's osrelease. The SDK's bug is that it matches "Microsoft"
			// case-sensitively; this locks the case-insensitive match from the
			// other direction.
			name:  "osrelease only: uppercase Microsoft (WSL1)",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "4.4.0-19041-Microsoft"},
			want:  true,
		},
		{
			name:  "osrelease only: microsoft token",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "5.15.0-microsoft-standard"},
			want:  true,
		},
		{
			name:  "osrelease only: wsl token, no microsoft, no WSL2",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "5.15.0-WSL-custom"},
			want:  true,
		},
		{
			name:  "osrelease only: uppercase WSL2 marker",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "5.15.0-generic-WSL2"},
			want:  true,
		},
		{
			// The WSL_* env vars are no longer signals. WSL's init sets
			// WSL_DISTRO_NAME in the same unconditional function that creates
			// /run/WSL under FATAL_ERROR (src/linux/init/config.cpp), so this
			// combination — env vars set, every marker absent, osrelease clean —
			// is not reachable on a real WSL system. Treating it as WSL would be a
			// pure false positive.
			name: "WSL_* env vars alone are not a signal",
			goos: "linux",
			env: map[string]string{
				"WSL_DISTRO_NAME": "Ubuntu-22.04",
				"WSL_INTEROP":     "/run/WSL/424_interop",
			},
			want: false,
		},
		{
			name:  "plain linux",
			goos:  "linux",
			files: map[string]string{procOSReleasePath: "6.8.0-51-generic"},
			want:  false,
		},
		{
			name: "osrelease unreadable and nothing else present",
			goos: "linux",
			want: false,
		},
		{
			name:   "non-linux GOOS never touches the filesystem or environment",
			goos:   "windows",
			files:  map[string]string{procOSReleasePath: "microsoft"},
			exists: []string{runWSLPath},
			env:    map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessed := false
			d := Detector{
				ReadFile: func(name string) ([]byte, error) {
					accessed = true
					return fakeFS(tt.files)(name)
				},
				Exists: func(path string) bool {
					accessed = true
					return fakeExists(tt.exists...)(path)
				},
				LookupEnv: func(key string) (string, bool) {
					accessed = true
					return fakeEnv(tt.env)(key)
				},
				GOOS: tt.goos,
			}
			if got := d.IsWSL(); got != tt.want {
				t.Errorf("IsWSL() = %v, want %v", got, tt.want)
			}
			if signal, ok := d.wslSignal(); tt.wantSignal != "" && (!ok || signal != tt.wantSignal) {
				t.Errorf("wslSignal() = %q (found=%v), want %q — precedence order changed", signal, ok, tt.wantSignal)
			}
			if tt.goos != "linux" && accessed {
				t.Error("IsWSL() read the filesystem or environment on non-linux GOOS; expected short-circuit")
			}
		})
	}
}

// TestProcVersionIsNeverRead locks the removal of the /proc/version signal.
//
// The kernel builds /proc/version from utsname()->release
// (fs/proc/version.c: seq_printf(m, linux_proc_banner, ..., utsname()->release,
// ...)), and /proc/sys/kernel/osrelease *is* that field
// (kernel/utsname_sysctl.c: uts_kern_table entry "osrelease" ->
// init_uts_ns.name.release). So "microsoft" in the release component of
// /proc/version can never match without osrelease matching first. Everything
// else in that file — build user, build host, compiler banner — is a false
// positive source, not extra coverage.
//
// Reading it again would reintroduce exactly that: this fixture is a plain
// Linux box whose kernel was built on a host named "microsoft-builder".
func TestProcVersionIsNeverRead(t *testing.T) {
	const procVersionPath = "/proc/version"

	var readPaths []string
	d := Detector{
		ReadFile: func(name string) ([]byte, error) {
			readPaths = append(readPaths, name)
			return fakeFS(map[string]string{
				procVersionPath:   "Linux version 6.8.0-51-generic (builder@microsoft-builder) (gcc (GCC) 13.2.0)",
				procOSReleasePath: "6.8.0-51-generic",
			})(name)
		},
		Exists:    fakeExists(),
		LookupEnv: fakeEnv(nil),
		GOOS:      "linux",
	}

	if d.IsWSL() {
		t.Error("IsWSL() = true on a plain Linux box; /proc/version must not be a signal")
	}
	for _, p := range readPaths {
		if p == procVersionPath {
			t.Errorf("read %s; it is redundant with %s and must not be consulted", procVersionPath, procOSReleasePath)
		}
	}
}

// TestWSLSignalReadsNoEnvVars locks the removal of the WSL_DISTRO_NAME /
// WSL_INTEROP signals.
//
// WSL's init sets WSL_DISTRO_NAME in ConfigInitializeInstance()
// (src/linux/init/config.cpp), the same function that ~100 lines later, with no
// conditional in between, creates /run/WSL under FATAL_ERROR. A process can
// therefore never see WSL_DISTRO_NAME on a distro that did not create
// /run/WSL, which makes the var strictly narrower than the marker. It is also
// absent exactly where the marker still works (sudo -i, systemd units, cron,
// ssh), so re-adding it would buy nothing and only add false positives.
//
// Note this pins wslSignal specifically — Apply() still reads LookupEnv for the
// IDSEC_BASIC_KEYRING precedence check, which must keep working.
func TestWSLSignalReadsNoEnvVars(t *testing.T) {
	var lookedUp []string
	d := Detector{
		ReadFile:  fakeFS(map[string]string{procOSReleasePath: "6.8.0-51-generic"}),
		Exists:    fakeExists(),
		LookupEnv: func(key string) (string, bool) { lookedUp = append(lookedUp, key); return "Ubuntu-22.04", true },
		GOOS:      "linux",
	}

	if d.IsWSL() {
		t.Error("IsWSL() = true with every marker absent; the WSL_* env vars must not be signals")
	}
	if len(lookedUp) != 0 {
		t.Errorf("wslSignal looked up env vars %v; they are redundant with %s and must not be consulted", lookedUp, runWSLPath)
	}
}

func TestDetectorApply(t *testing.T) {
	wslFiles := map[string]string{procOSReleasePath: "6.18.33.2-microsoft-standard-WSL2"}
	plainFiles := map[string]string{procOSReleasePath: "6.8.0-51-generic"}

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
			accessed := false
			d := Detector{
				ReadFile: func(name string) ([]byte, error) {
					accessed = true
					return fakeFS(tt.files)(name)
				},
				Exists: func(path string) bool {
					accessed = true
					return fakeExists()(path)
				},
				LookupEnv: func(key string) (string, bool) {
					accessed = true
					return fakeEnv(tt.env)(key)
				},
				Setenv: func(k, v string) error {
					accessed = true
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
			if tt.goos != "linux" && accessed {
				t.Error("Apply() read the filesystem or environment, or wrote an env var, on non-linux GOOS; expected short-circuit")
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
