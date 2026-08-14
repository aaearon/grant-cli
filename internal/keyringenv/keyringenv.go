// Package keyringenv detects WSL and forces the SDK's file-based ("basic")
// keyring backend before any keyring access happens.
//
// Why: idsec-sdk-golang's GetKeyring picks the OS-provided (D-Bus/libsecret)
// keyring on Linux whenever DBUS_SESSION_BUS_ADDRESS is set. Its own WSL guard
// matches "Microsoft" case-sensitively against /proc/version, which modern WSL2
// kernels (".. -microsoft-standard-WSL2") do not satisfy. Under WSLg that D-Bus
// call can block forever, and the SDK's fallbacks only trigger on a returned
// error — a hang is never an error, so it is unrecoverable. Setting
// IDSEC_BASIC_KEYRING is the only lever available without vendoring the SDK.
package keyringenv

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	// envVar is the SDK's IdsecBasicKeyringOverrideEnvVar. The SDK checks
	// os.Getenv(envVar) != "", so ANY non-empty value forces the basic keyring.
	envVar = "IDSEC_BASIC_KEYRING"

	procVersionPath   = "/proc/version"
	procOSReleasePath = "/proc/sys/kernel/osrelease"
)

// Detector inspects the environment for WSL and applies the keyring override.
// The zero value is not usable; use New or the package-level Apply.
type Detector struct {
	ReadFile  func(string) ([]byte, error)
	LookupEnv func(string) (string, bool)
	Setenv    func(string, string) error
	GOOS      string
}

// New returns a Detector wired to the real OS.
func New() Detector {
	return Detector{
		ReadFile:  os.ReadFile,
		LookupEnv: os.LookupEnv,
		Setenv:    os.Setenv,
		GOOS:      runtime.GOOS,
	}
}

// IsWSL reports whether the current process runs under WSL. It is a no-op
// (false) off Linux. Unreadable /proc files are "no signal", never an error.
func (d Detector) IsWSL() bool {
	_, ok := d.wslSignal()
	return ok
}

// wslSignal returns the first WSL indicator found, and whether one was found.
func (d Detector) wslSignal() (string, bool) {
	if d.GOOS != "linux" {
		return "", false
	}
	// Both files are checked for both tokens: "microsoft" catches the standard
	// kernel strings, "wsl" catches custom kernels that only carry the WSL/WSL2
	// marker. Matching is case-insensitive — that is the SDK's actual bug.
	for _, path := range []string{procVersionPath, procOSReleasePath} {
		data, err := d.ReadFile(path)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, token := range []string{"microsoft", "wsl"} {
			if strings.Contains(lower, token) {
				return path, true
			}
		}
	}
	for _, key := range []string{"WSL_DISTRO_NAME", "WSL_INTEROP"} {
		if v, ok := d.LookupEnv(key); ok && v != "" {
			return key, true
		}
	}
	return "", false
}

// Apply forces the SDK's file-based keyring when running under WSL.
//
// It reports whether the override was applied and a human-readable reason.
// An existing non-empty IDSEC_BASIC_KEYRING is always preserved: any non-empty
// value already forces the safe basic keyring. An explicitly-empty value is
// the dangerous case — it selects the OS keyring — so on WSL it is treated
// exactly like unset and overwritten.
//
// Apply fails closed: a Setenv error is returned so the caller can abort
// rather than walk the user into a hang with no timeout.
func (d Detector) Apply() (applied bool, reason string, err error) {
	if d.GOOS != "linux" {
		return false, "not linux; keyring override not needed", nil
	}
	if v, ok := d.LookupEnv(envVar); ok && v != "" {
		return false, envVar + " already set; leaving it alone", nil
	}
	signal, isWSL := d.wslSignal()
	if !isWSL {
		return false, "not WSL; keyring override not needed", nil
	}
	if err := d.Setenv(envVar, "1"); err != nil {
		return false, "", fmt.Errorf("setting %s: %w", envVar, err)
	}
	return true, fmt.Sprintf("WSL detected (%s); forcing the file-based keyring via %s=1", signal, envVar), nil
}

// Apply runs the detector against the real OS environment.
func Apply() (applied bool, reason string, err error) {
	return New().Apply()
}
