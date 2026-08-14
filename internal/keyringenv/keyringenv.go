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

	// runWSLPath is the marker directory the WSL init creates. It is the only
	// signal that survives custom kernels, sudo, systemd units and cron, where
	// the WSL_* env vars are absent (microsoft/WSL#5914, #9719) and a custom
	// kernel may carry neither "microsoft" nor "wsl" in its version strings
	// (microsoft/WSL#6911). snapd moved to exactly this marker after
	// Launchpad #1991823.
	runWSLPath = "/run/WSL"

	// wslInteropPath is a supplement to runWSLPath, never a replacement — that
	// insufficiency is what Launchpad #1991823 documents. On WSL1 the
	// per-distro registration is gated on Config.InteropEnabled
	// (src/linux/init/config.cpp), so disabling interop in wsl.conf removes it;
	// on WSL2 the entry is registered VM-wide and is kernel-global, so it can
	// be wiped or shadowed for every distro at once. It is also absent in any
	// mount namespace that does not mount binfmt_misc.
	wslInteropPath = "/proc/sys/fs/binfmt_misc/WSLInterop"
)

// Detector inspects the environment for WSL and applies the keyring override.
// The zero value is not usable; use New or the package-level Apply.
type Detector struct {
	ReadFile  func(string) ([]byte, error)
	Exists    func(string) bool
	LookupEnv func(string) (string, bool)
	Setenv    func(string, string) error
	GOOS      string
}

// New returns a Detector wired to the real OS.
func New() Detector {
	return Detector{
		ReadFile: os.ReadFile,
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		LookupEnv: os.LookupEnv,
		Setenv:    os.Setenv,
		GOOS:      runtime.GOOS,
	}
}

// IsWSL reports whether the current process runs under WSL. It is a no-op
// (false) off Linux. Unreadable /proc files are "no signal", never an error.
//
// There is no supported Microsoft API for this; the de-facto reference is
// microsoft/WSL#423, which systemd follows in src/basic/virt.c.
//
// The errors are asymmetric, which is what drives the tuning:
//   - a false negative attempts the OS keyring under WSLg, which can block
//     indefinitely with no error and no timeout — unrecoverable;
//   - a false positive uses a file-based keyring on a plain Linux desktop — a
//     real but bounded security downgrade.
//
// So bias toward over-detection, but via the /run/WSL marker, which is
// simultaneously broader and more specific, not via looser string matching.
func (d Detector) IsWSL() bool {
	_, ok := d.wslSignal()
	return ok
}

// wslSignal returns the first WSL indicator found, and whether one was found.
//
// All five signals are deliberately kept. The redundancy is about VISIBILITY,
// not reliability, and that is why "this one is weaker" is never on its own a
// reason to delete one — they fail independently because each is reached by a
// different mechanism:
//
//   - the filesystem markers are namespace-local: a chroot or mount namespace
//     with a clean /run, or without binfmt_misc mounted, sees neither, whatever
//     WSL's init did;
//   - the two proc paths are independently maskable, being separate
//     mount-visible paths;
//   - the env vars are the only signal inherited ACROSS chroot and
//     mount-namespace boundaries — exactly where every marker above vanishes.
//
// Beware the trap that produced (and reverted) commit db73645: content
// equivalence is not signal redundancy. /proc/version and osrelease provably
// cannot disagree — the kernel renders both from utsname()->release via the
// caller's UTS namespace (fs/proc/version.c; kernel/utsname_sysctl.c) — and
// init sets WSL_DISTRO_NAME and creates /run/WSL in the same unguarded
// function. Neither fact means a given process can still SEE the other source.
// Only delete a signal you can show is unreachable-when-the-others-are-not.
func (d Detector) wslSignal() (string, bool) {
	if d.GOOS != "linux" {
		return "", false
	}
	// Filesystem markers first: they are both broader and more specific than
	// string matching, and they are what covers custom kernels.
	for _, path := range []string{runWSLPath, wslInteropPath} {
		if d.Exists(path) {
			return path, true
		}
	}
	// Then the kernel strings, case-insensitively — the case sensitivity is the
	// SDK's actual bug. The token sets differ deliberately:
	//   - osrelease is short and structured ("6.18.33.2-microsoft-standard-WSL2"),
	//     so matching "wsl" there is safe. systemd does this (Microsoft||WSL on
	//     osrelease). npm's is-wsl does NOT: it matches only "microsoft", on
	//     os.release() and then /proc/version, before falling back to the two
	//     filesystem markers below — all gated behind !isInsideContainer().
	//   - /proc/version is free-form and carries the kernel build user, build
	//     host and full compiler banner, so a bare "wsl" would match a plain
	//     Linux box built by user "wsl" or on host "wsl-builder". "microsoft"
	//     only.
	for _, f := range []struct {
		path   string
		tokens []string
	}{
		{procOSReleasePath, []string{"microsoft", "wsl"}},
		{procVersionPath, []string{"microsoft"}},
	} {
		data, err := d.ReadFile(f.path)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, token := range f.tokens {
			if strings.Contains(lower, token) {
				return f.path, true
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
