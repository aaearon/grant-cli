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

	// procOSReleasePath exposes utsname()->release. /proc/version is NOT read:
	// the kernel builds it from the very same field, so it can never be the
	// deciding signal. See the note on wslSignal.
	procOSReleasePath = "/proc/sys/kernel/osrelease"

	// runWSLPath is the load-bearing marker. WSL's init creates it in
	// InteropServer::Create() (src/linux/init/util.cpp, WSL_TEMP_FOLDER =
	// RUN_FOLDER "/WSL"), called unconditionally from ConfigInitializeInstance()
	// (src/linux/init/config.cpp) under FATAL_ERROR — a distro that cannot
	// create it does not boot. Not gated on the wsl.conf interop setting, not
	// gated on WSL1-vs-WSL2, and independent of the kernel, so it survives
	// custom kernels (microsoft/WSL#6911), sudo, systemd units and cron. snapd
	// moved to this marker after Launchpad #1991823; npm's is-wsl uses it too.
	runWSLPath = "/run/WSL"

	// wslInteropPath is a supplement to runWSLPath, never a replacement: on
	// WSL1 the per-distro registration is gated on Config.InteropEnabled
	// (src/linux/init/config.cpp), and on WSL2 the VM-level entry is
	// kernel-global, so systemd-binfmt can shadow it under a different name
	// (microsoft/WSL#13449). That insufficiency is what Launchpad #1991823
	// documents.
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
// Three signals, deliberately. Two more were considered and removed as
// redundant — redundant meaning every configuration they detect is already
// detected by one of the three, not merely that they are weaker:
//
//   - /proc/version. See the note below.
//   - WSL_DISTRO_NAME / WSL_INTEROP. WSL's init sets WSL_DISTRO_NAME in
//     ConfigInitializeInstance() (src/linux/init/config.cpp), the same function
//     that, ~100 lines later and with no conditional between them, creates
//     /run/WSL under FATAL_ERROR. So WSL_DISTRO_NAME cannot be set in a process
//     whose distro did not create /run/WSL — the var is strictly narrower.
//     WSL_INTEROP is narrower still: it is exported only when interop is
//     enabled (src/linux/init/init.cpp). They also point the wrong way for our
//     error asymmetry, being absent under `sudo -i` (microsoft/WSL#5914), in
//     systemd units (#9719), in cron and over SSH, exactly where /run/WSL keeps
//     working. snapd and npm's is-wsl both decline to check them.
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
	// Then the kernel release string, case-insensitively — the case sensitivity
	// is the SDK's actual bug. osrelease is short and structured
	// ("6.18.33.2-microsoft-standard-WSL2"), so matching "wsl" there is safe;
	// systemd does the same (Microsoft||WSL on osrelease, src/basic/virt.c).
	//
	// /proc/version is deliberately NOT read. The kernel formats it as
	// linux_proc_banner with utsname()->release as its second %s
	// (fs/proc/version.c version_proc_show), and /proc/sys/kernel/osrelease is
	// that identical field (kernel/utsname_sysctl.c, uts_kern_table entry
	// "osrelease" -> init_uts_ns.name.release, resolved per-namespace by
	// get_uts). So "microsoft" in /proc/version's release component can never
	// match without osrelease matching too. Its remaining substrings are the
	// build user, build host and compiler banner, where a match is a false
	// positive, not coverage — a plain Linux box built on a host named
	// "microsoft-builder" would trip it. WSL1 exposes osrelease as well
	// ("4.4.0-19041-Microsoft"); the WSL team named both files together in
	// microsoft/WSL#423.
	data, err := d.ReadFile(procOSReleasePath)
	if err == nil {
		lower := strings.ToLower(string(data))
		for _, token := range []string{"microsoft", "wsl"} {
			if strings.Contains(lower, token) {
				return procOSReleasePath, true
			}
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
